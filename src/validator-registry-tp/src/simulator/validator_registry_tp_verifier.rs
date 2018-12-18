/*
 * Copyright 2018 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */

use sawtooth_sdk::processor::handler::TransactionContext;
use validator_registry_payload::ValidatorRegistryPayload;
use validator_registry_tp::ValueError;

pub fn verify_signup_info(
    _context: &mut TransactionContext,
    _originator_public_key_hash: &str,
    _val_reg_payload: &ValidatorRegistryPayload,
) -> Result<(), ValueError> {
    // In simulator mode, always return success.
    Ok(())
}
