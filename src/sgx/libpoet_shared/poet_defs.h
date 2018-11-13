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

#pragma once

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif // _cplusplus

    typedef enum {
        POET_SUCCESS=0,
        POET_ERR_UNKNOWN=-1,
        POET_ERR_MEMORY=-2,
        POET_ERR_IO =-3,
        POET_ERR_RUNTIME=-4,
        POET_ERR_INDEX=-5,
        POET_ERR_DIVIDE_BY_ZERO=-6,
        POET_ERR_OVERFLOW =-7,
        POET_ERR_VALUE =-8,
        POET_ERR_SYSTEM =-9,
        POET_ERR_SYSTEM_BUSY =-10   /*
                                        Indicates that the system is busy and
                                        the operation may be retried again.  If
                                        retries fail this should be converted to
                                        a POET_ERR_SYSTEM for reporting.
                                    */
    } poet_err_t;

    typedef enum {
        POET_LOG_DEBUG = 0,
        POET_LOG_INFO = 1,
        POET_LOG_WARNING = 2,
        POET_LOG_ERROR = 3,
        POET_LOG_CRITICAL = 4,
    } poet_log_level_t;

    typedef void (*poet_log_t)(
        poet_log_level_t,
        const char* message
        );    

#ifdef __cplusplus
};
#endif // _cplusplus
