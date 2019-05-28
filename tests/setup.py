# Copyright 2018 Intel Corporation
# Copyright 2019 Cargill Incorporated
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

from __future__ import print_function

import os
import subprocess

from setuptools import setup, find_packages


data_files = []

def add_data_files(package_dir, search_dir):
    if os.path.exists(search_dir):
        for root, dirs, files in os.walk(search_dir):
            dirs.clear()
            for file in files:
                data_files.append((package_dir, [os.path.join(root,file)]))

add_data_files("/data/tests/poet", "sawtooth_poet_tests")
add_data_files("/data/tests/poet/poet_liveness_data",
    "sawtooth_poet_tests/poet_liveness_data")

data_files.append(('/data/tests/poet', ['../simulator/packaging/simulator_rk_pub.pem']))

setup(
    name='sawtooth-poet-tests',
    version=subprocess.check_output(
        ['../bin/get_version']).decode('utf-8').strip(),
    description='Sawtooth PoET Tests',
    author='Hyperledger Sawtooth',
    url='https://github.com/hyperledger/sawtooth-poet',
    packages=find_packages(),
    install_requires=[],
    data_files=data_files,
    entry_points={}
)
