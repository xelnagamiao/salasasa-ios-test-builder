"""Standard-library validation/state helper. Never signs or contacts an account."""
import argparse
import hashlib
import json
import pathlib
import plistlib
import struct
import sys
import zipfile

CONTRACT = {"unityVersion": "6000.3.28f1", "marketingVersion": "0.5.89", "buildNumber": "34",
            "releaseVersion": 34, "bundleId": "com.Salasasa-Studio.open-mahjong-unity"}


def digest(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def tree_digest(root):
    root = pathlib.Path(root).resolve()
    h = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.name == '.DS_Store':
            continue
        h.update(path.relative_to(root).as_posix().encode('utf-8') + b'\0')
        h.update(digest(path).encode('ascii') + b'\n')
    return h.hexdigest()


def validate_export(root):
    root = pathlib.Path(root).resolve()
    result = json.loads((root / 'salasasa-export-result.json').read_text(encoding='utf-8-sig'))
    if result.get('success') is not True:
        raise ValueError('No successful Unity export receipt')
    for key, value in CONTRACT.items():
        if result.get(key) != value:
            raise ValueError('Export receipt mismatch: ' + key)
    if result.get('scene') != 'Assets/Scenes/MainScene.unity':
        raise ValueError('Unexpected build scene')
    if not (root / 'Unity-iPhone.xcodeproj/project.pbxproj').is_file():
        raise ValueError('Xcode project missing')
    validate_plist(plistlib.loads((root / 'Info.plist').read_bytes()), platform=False)
    return result


def validate_plist(info, platform=True):
    checks = {'CFBundleIdentifier': CONTRACT['bundleId'], 'CFBundleShortVersionString': '0.5.89', 'CFBundleVersion': '34'}
    for key, value in checks.items():
        if info.get(key) != value:
            raise ValueError('Info.plist mismatch: ' + key)
    if platform:
        if info.get('CFBundlePackageType') != 'APPL':
            raise ValueError('Not an application bundle')
        if 'iPhoneOS' not in info.get('CFBundleSupportedPlatforms', []):
            raise ValueError('Not an iPhoneOS device application')
    executable = info.get('CFBundleExecutable')
    if platform and (not isinstance(executable, str) or not executable or '/' in executable or '\\' in executable):
        raise ValueError('Invalid application executable name')
    return executable


def require_device_macho(stream, file_size, file_type):
    """Validate actual ARM64 slices, load commands, device platform and text bytes.

    Constants/layout follow Apple's mach-o/loader.h and fat.h. This is a
    structural gate, not a substitute for the linker or a real-device launch.
    """
    def read_at(offset, size):
        if offset < 0 or size < 0 or offset + size > file_size:
            raise ValueError('Mach-O range exceeds file size')
        stream.seek(offset)
        value = stream.read(size)
        if len(value) != size: raise ValueError('Truncated Mach-O data')
        return value

    header = read_at(0, 8)
    slices = [(0, file_size)]
    if header[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
        count = struct.unpack('>I', header[4:8])[0]
        stride = 32 if header[3] == 0xbf else 20
        if not 0 < count <= 32: raise ValueError('Invalid FAT architecture count')
        table_end = 8 + count * stride
        table = read_at(8, count * stride)
        slices, ranges = [], []
        for index in range(count):
            row = table[index * stride:(index + 1) * stride]
            cpu, subtype = struct.unpack_from('>II', row)
            offset, size = struct.unpack_from('>QQ' if stride == 32 else '>II', row, 8)
            align = struct.unpack_from('>I', row, 24 if stride == 32 else 16)[0]
            if offset < table_end or size < 32 or offset + size > file_size or align > 30 or offset % (1 << align):
                raise ValueError('Invalid FAT slice range/alignment')
            if any(offset < end and start < offset + size for start, end in ranges):
                raise ValueError('Overlapping FAT slices')
            ranges.append((offset, offset + size))
            if cpu == 0x0100000c: slices.append((offset, size))
        if not slices: raise ValueError('No ARM64 Mach-O slice')

    signatures = []
    for base, size in slices:
        if size < 32: raise ValueError('Missing Mach-O header')
        values = struct.unpack('<8I', read_at(base, 32))
        magic, cpu, subtype, kind, ncmds, command_bytes, flags, reserved = values
        if magic != 0xfeedfacf or cpu != 0x0100000c or kind != file_type:
            raise ValueError('Expected ARM64 MH_EXECUTE' if file_type == 2 else 'Expected ARM64 MH_DYLIB')
        if not 0 < ncmds <= 65536 or command_bytes > min(size - 32, 16 * 1024 * 1024):
            raise ValueError('Invalid Mach-O load-command region')
        commands = read_at(base + 32, command_bytes)
        cursor, platforms, text_sections, signature = 0, [], [], False
        for _ in range(ncmds):
            if cursor + 8 > command_bytes: raise ValueError('Truncated Mach-O load command')
            command, length = struct.unpack_from('<II', commands, cursor)
            if length < 8 or length % 8 or cursor + length > command_bytes:
                raise ValueError('Invalid Mach-O load-command size')
            data = commands[cursor:cursor + length]
            if command == 0x32:  # LC_BUILD_VERSION
                if length < 24: raise ValueError('Truncated build-version command')
                platform, minimum, sdk, tools = struct.unpack_from('<4I', data, 8)
                if length != 24 + tools * 8: raise ValueError('Invalid build-version tool array')
                platforms.append(platform)
            elif command in (0x24, 0x25, 0x2f, 0x30):  # Legacy version-min commands
                if length != 16: raise ValueError('Invalid minimum-version command')
                platforms.append({0x24: 1, 0x25: 2, 0x2f: 3, 0x30: 4}[command])
            elif command == 0x19:  # LC_SEGMENT_64 and section_64 entries
                if length < 72: raise ValueError('Truncated segment command')
                fileoff, filesize = struct.unpack_from('<QQ', data, 40)
                initprot, sections = struct.unpack_from('<II', data, 60)
                if length != 72 + sections * 80 or fileoff + filesize > size:
                    raise ValueError('Invalid Mach-O segment range')
                for index in range(sections):
                    section = 72 + index * 80
                    name = data[section:section + 16].split(b'\0', 1)[0]
                    section_size = struct.unpack_from('<Q', data, section + 40)[0]
                    section_offset = struct.unpack_from('<I', data, section + 48)[0]
                    section_type = struct.unpack_from('<I', data, section + 64)[0] & 0xff
                    if section_type not in (1, 0xc, 0x12) and section_size:
                        if section_offset < fileoff or section_offset + section_size > fileoff + filesize:
                            raise ValueError('Mach-O section exceeds its file segment')
                    if name == b'__text' and initprot & 4 and section_type not in (1, 0xc, 0x12):
                        if section_size < 4 or section_offset < 32 + command_bytes:
                            raise ValueError('Missing executable text bytes')
                        text_sections.append((section_offset, section_size))
            elif command == 0x1d:  # LC_CODE_SIGNATURE; report, do not strip vendor/adhoc signatures
                if length != 16: raise ValueError('Invalid code-signature command')
                offset, length_bytes = struct.unpack_from('<II', data, 8)
                if not length_bytes or offset + length_bytes > size:
                    raise ValueError('Code-signature range exceeds Mach-O slice')
                signature = True
            cursor += length
        if cursor != command_bytes: raise ValueError('Mach-O command count/size mismatch')
        if not platforms or any(platform != 2 for platform in platforms):
            raise ValueError('Mach-O is not built for iOS devices (platform 2)')
        if not text_sections: raise ValueError('Mach-O has no executable __text section')
        signatures.append(signature)
    return {'arm64DeviceSlices': len(slices), 'hasCodeSignatureCommand': any(signatures)}


def validate_unity_layout(open_file, size_of):
    framework = 'Frameworks/UnityFramework.framework/'
    if size_of(framework + 'Info.plist') == 0 or size_of(framework + 'UnityFramework') == 0:
        raise ValueError('UnityFramework bundle is missing')
    with open_file(framework + 'Info.plist') as stream:
        info = plistlib.load(stream)
    if info.get('CFBundlePackageType') != 'FMWK' or info.get('CFBundleExecutable') != 'UnityFramework':
        raise ValueError('UnityFramework bundle metadata is missing or invalid')
    if 'iPhoneOS' not in info.get('CFBundleSupportedPlatforms', []):
        raise ValueError('UnityFramework is not an iPhoneOS device framework')
    binary = framework + 'UnityFramework'
    with open_file(binary) as stream:
        framework_info = require_device_macho(stream, size_of(binary), 6)
    data_root = None
    for candidate in ('Data/', framework + 'Data/'):
        metadata = candidate + 'Managed/Metadata/global-metadata.dat'
        if size_of(metadata) < 32: continue
        with open_file(metadata) as stream: header = stream.read(12)
        sanity, version, header_bytes = struct.unpack('<III', header)
        # Confirmed in installed 6000.3.28f1 libil2cpp/vm/GlobalMetadata.cpp.
        if sanity != 0xfab11baf or version != 39 or not 32 <= header_bytes <= size_of(metadata):
            continue
        if size_of(candidate + 'globalgamemanagers') > 0:
            data_root = candidate
            break
        if size_of(candidate + 'data.unity3d') > 8:
            with open_file(candidate + 'data.unity3d') as stream: magic = stream.read(8)
            if magic == b'UnityFS\0':
                data_root = candidate
                break
    if data_root is None:
        raise ValueError('Unity Data missing/incomplete: expected IL2CPP v39 metadata and globalgamemanagers or data.unity3d')
    return {'framework': framework_info, 'dataRoot': data_root}


def validate_app(path):
    path = pathlib.Path(path).resolve()
    executable = validate_plist(plistlib.loads((path / 'Info.plist').read_bytes()))
    with (path / executable).open('rb') as stream:
        main = require_device_macho(stream, (path / executable).stat().st_size, 2)
    unity = validate_unity_layout(lambda name: (path / name).open('rb'),
                                  lambda name: (path / name).stat().st_size if (path / name).is_file() else 0)
    if (path / '_CodeSignature').exists():
        raise ValueError('Unexpected signed app; this kit produces unsigned artifacts only')
    return {'app': str(path), 'treeSha256': tree_digest(path), 'mainExecutable': main, 'unity': unity}


def inspect_ipa(path):
    path = pathlib.Path(path)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)): raise ValueError('Duplicate ZIP entry names')
        plists = [name for name in names if name.startswith('Payload/') and name.count('/') == 2 and name.endswith('.app/Info.plist')]
        if len(plists) != 1:
            raise ValueError('IPA must contain exactly one Payload/*.app/Info.plist')
        bad = archive.testzip()
        if bad:
            raise ValueError('ZIP CRC failure: ' + bad)
        executable = validate_plist(plistlib.loads(archive.read(plists[0])))
        app_prefix = plists[0][:-len('Info.plist')]
        with archive.open(app_prefix + executable) as stream:
            main = require_device_macho(stream, archive.getinfo(app_prefix + executable).file_size, 2)
        files = {entry.filename: entry.file_size for entry in archive.infolist() if not entry.is_dir()}
        unity = validate_unity_layout(lambda name: archive.open(app_prefix + name),
                                      lambda name: files.get(app_prefix + name, 0))
        if any(name.startswith(app_prefix + '_CodeSignature/') for name in names):
            raise ValueError('IPA unexpectedly contains a signing directory')
    return {'file': path.name, 'sizeBytes': path.stat().st_size, 'sha256': digest(path),
            'signed': False, 'signingMeaning': 'App bundle has no signing directory; embedded Mach-O signature commands are reported separately.',
            'mainExecutable': main, 'unity': unity, 'installableWithoutSigning': False, **CONTRACT}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['export', 'app', 'ipa', 'fingerprint', 'state-write', 'state-check'])
    parser.add_argument('path')
    parser.add_argument('--export-path')
    parser.add_argument('--app-path')
    parser.add_argument('--json-output')
    args = parser.parse_args()
    if args.action == 'export': result = validate_export(args.path)
    elif args.action == 'app': result = validate_app(args.path)
    elif args.action == 'ipa': result = inspect_ipa(args.path)
    elif args.action == 'fingerprint': result = {'sha256': tree_digest(args.path)}
    elif args.action == 'state-write':
        validate_export(args.export_path)
        result = {'exportPath': str(pathlib.Path(args.export_path).resolve()), 'exportSha256': tree_digest(args.export_path),
                  'app': validate_app(args.app_path), **CONTRACT}
        pathlib.Path(args.path).write_text(json.dumps(result, indent=2), encoding='utf-8')
    else:
        result = json.loads(pathlib.Path(args.path).read_text(encoding='utf-8'))
        validate_export(args.export_path)
        for key, value in CONTRACT.items():
            if result.get(key) != value: raise ValueError('Build state contract changed: ' + key)
        if result['exportPath'] != str(pathlib.Path(args.export_path).resolve()) or result['exportSha256'] != tree_digest(args.export_path):
            raise ValueError('Xcode export changed; use a new output directory')
        if result['app'] != validate_app(result['app']['app']):
            raise ValueError('Compiled app changed; use a new output directory')
    if args.json_output:
        pathlib.Path(args.json_output).write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Artifact validation failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
