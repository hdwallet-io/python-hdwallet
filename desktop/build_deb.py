#!/usr/bin/env python3

# Copyright © 2020-2024, Meheret Tesfaye Batu <meherett.batu@gmail.com>
#             2024, Abenezer Lulseged Wube <itsm3abena@gmail.com>
#             2024, Eyoel Tadesse <eyoel_tadesse@proton.me>
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit

from pathlib import Path
from glob import glob

import sys
import shutil
import platform
import subprocess

from src.info import __version__, __name__, __author__, __description__

arch_map = {
    "x86_64": "amd64",
    "aarch64": "arm64",
    "armv7l": "armhf",
    "i386": "i386",
}
machine_arch = arch_map.get(platform.machine(), platform.machine()) 

if platform.system() != "Linux":
    print("Unable to create a .deb package on a non-Linux system!")
    sys.exit(1)


app_version = __version__.lstrip("v")
app_name  = "HDWallet"
app_description = __description__
maintainer = __author__ 

icon_path = "src/ui/images/svg/HDW-Logo.svg"

build_root = Path("./dist")
build_root.mkdir(exist_ok=True)

appimage_output_path = None

try:
    subprocess.run(["python3", "setup.py", "bdist_appimage"], check=True)
    dist_appimage_files = glob(f"dist/*.AppImage")
    if dist_appimage_files:
        appimage_output_path = dist_appimage_files[0]
    else:
        print("Failed to find the AppImage in 'dist' after build.")
        sys.exit(1)
except subprocess.CalledProcessError as e:
    print("Failed to build the AppImage:", e)
    sys.exit(1)

package_dir = build_root / app_name
deb_dir = package_dir / "DEBIAN"
applications_dir = package_dir / "usr/share/applications"
opt_dir = package_dir / f"opt/{app_name}"
icon_dir = package_dir / "usr/share/icons/hicolor/scalable/apps"

for dir_path in [deb_dir, applications_dir, opt_dir, icon_dir]:
    dir_path.mkdir(parents=True, exist_ok=True)

appimage_target_path = opt_dir / f"{app_name}.AppImage"
shutil.copy2(appimage_output_path, appimage_target_path)

appimage_target_path.chmod(0o755)

icon_target_path = icon_dir / f"{app_name}.svg"
shutil.copy2(icon_path, icon_target_path)

desktop_entry_content = f"""[Desktop Entry]
Name={app_name}
Exec=/opt/{app_name}/{app_name}.AppImage
Icon={app_name}
Type=Application
Categories=Utility;
Comment={app_description}.
"""
desktop_entry_path = applications_dir / f"{app_name}.desktop"
desktop_entry_path.write_text(desktop_entry_content)

def calculate_installed_size_kb(directory):
    total_size = sum(f.stat().st_size for f in directory.rglob('*') if f.is_file())
    return (total_size + 1023) // 1024  # Round

installed_size_kb = calculate_installed_size_kb(package_dir)

control_content = f"""Package: {app_name}
Version: {app_version}
Section: utils
Priority: optional
Architecture: {machine_arch}
Maintainer: {maintainer}
Installed-Size: {installed_size_kb}
Description: {app_description}
"""
control_file_path = deb_dir / "control"
control_file_path.write_text(control_content)

try:
    subprocess.run(["dpkg-deb", "--build", str(package_dir)], check=True)
    final_deb = f"{build_root}/{app_name}-{app_version}-{machine_arch}.deb"
    shutil.move(f"{build_root}/{app_name}.deb", final_deb)
    print(f"The .deb package has been created as {final_deb}")
    print(f"You can now install it with: sudo dpkg -i {final_deb}")
finally:
    shutil.rmtree(package_dir) # Clean up
