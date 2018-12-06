/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

#include <math.h>
#include <string>

class JSONBuilder {
public:
	JSONBuilder() {}

	virtual ~JSONBuilder() {}

	void jsonStart();

	void jsonSetString(std::string key, std::string value);

	void jsonSetUint64(std::string key, uint64_t value);

	void jsonEnd();

	std::string getJsonString();

private:
	void jsonAppendDelimiter();

	std::string jsonString;
}; // class JSONBuilder

