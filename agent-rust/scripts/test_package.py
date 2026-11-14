import json,pathlib,struct,tarfile,tempfile,unittest,zipfile
from package import identity,package
class PackageTests(unittest.TestCase):
 def elf(self,machine=62):
  data=bytearray(64);data[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',data,18,machine);return bytes(data)
 def test_native_platform_is_checked_instead_of_assumed(self):
  self.assertEqual(identity(self.elf()),('linux','x86_64'));self.assertEqual(identity(self.elf(183)),('linux','aarch64'))
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);binary=root/'binary';binary.write_bytes(self.elf())
   with self.assertRaises(ValueError):package(binary,'aarch64-apple-darwin',root/'out','a'*40,1700000000)
 def test_archive_repeats_exact_bytes_and_contains_no_configuration(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);binary=root/'binary';binary.write_bytes(self.elf());path=package(binary,'x86_64-unknown-linux-gnu',root/'one','a'*40,1700000000);other=package(binary,'x86_64-unknown-linux-gnu',root/'two','a'*40,1700000000);self.assertEqual(path.read_bytes(),other.read_bytes())
   with tarfile.open(path) as archive:
    self.assertEqual(set(archive.getnames()),{'od-agent-service','manifest.json','README.md'});self.assertEqual(archive.getmember('od-agent-service').mode,0o755);self.assertEqual(json.load(archive.extractfile('manifest.json'))['architecture'],'x86_64')
 def test_windows_header_and_package_match(self):
  raw=bytearray(128);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,64);raw[64:68]=b'PE\0\0';struct.pack_into('<H',raw,68,0x8664)
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory);binary=root/'agent.exe';binary.write_bytes(raw);path=package(binary,'x86_64-pc-windows-msvc',root/'out','a'*40,1700000000)
   with zipfile.ZipFile(path) as archive:self.assertEqual(set(archive.namelist()),{'od-agent-service.exe','manifest.json','README.md'})
if __name__=='__main__':unittest.main()
