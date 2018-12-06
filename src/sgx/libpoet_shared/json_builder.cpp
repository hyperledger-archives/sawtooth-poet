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

#include <stdio.h>
#include <math.h>
#include <string>
#include "json_builder.h"

void JSONBuilder::jsonStart()
{
	jsonString.append("{");
}

void JSONBuilder::jsonAppendDelimiter()
{
	jsonString.append(",");
}

void JSONBuilder::jsonSetString(std::string key, std::string value)
{
	jsonString.append("\"");
	jsonString.append(key);
	jsonString.append("\":");
	jsonString.append("\"");
	jsonString.append(value);
	jsonString.append("\"");

	jsonAppendDelimiter();
}

void JSONBuilder::jsonSetUint64(std::string key, uint64_t value)
{
	jsonString.append("\"");
	jsonString.append(key);
	jsonString.append("\":");

	char buf[sizeof(value)];
	snprintf(buf, sizeof(value), "%lu", value);
	jsonString.append(buf);

	jsonAppendDelimiter();
}

void JSONBuilder::jsonEnd()
{
	//delete delimeter if present at the end of string
	if (jsonString.at(jsonString.length()-1) == ',') {
		jsonString.pop_back();
	}

	jsonString.append("}");
}

std::string JSONBuilder::getJsonString()
{
	return jsonString;
}

