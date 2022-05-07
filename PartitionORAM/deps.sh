# Copyright (c) 2022 Haobin Chen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
system_name=$(uname -a)

# Check if the current system is Ubuntu.
if [[ $system_name =~ "Ubuntu" ]]; then
  echo "You are running Ubuntu. Now install dependencies."
else
  echo "You are not running Ubuntu. Please install dependencies manually."
  exit 1
fi

sudo apt install -y libspdlog-dev libgflags-dev libsodium-dev

# Clone the grpc repository.
git clone --recursive https://github.com/grpc/grpc.git
echo "Clone the grpc repository successfully."
echo "You can now build the grpc library by CMake following the official guide."