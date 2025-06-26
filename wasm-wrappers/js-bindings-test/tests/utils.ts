// Copyright (c) 2021-2025 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

export const TEXT_ENCODER = new TextEncoder();

type AnyArray = any[] | Uint8Array;

export function assert_eq_vals(val1: any, val2: any) {
  assert(val1 == val2, `val1 ${val1} differs from val2 ${val2}`)
}

export function assert_eq_arrays(arr1: AnyArray, arr2: AnyArray) {
  const equal = arr1.length == arr2.length && arr1.every((value, index) => value == arr2[index]);

  assert(equal, `array1 [${arr1}] differs from array2 [${arr2}]`);
}

export function assert(condition: any, message: any) {
  if (!condition) {
    throw Error('Assertion failed: ' + (message || ''));
  }
}

export function run_one_test(test_func: () => void) {
  console.group(`Running ${test_func.name}`);
  test_func();
  console.groupEnd();
}

export function get_err_msg(error: unknown) {
  if (error instanceof Error) return error.message
  return String(error)
}

// Generate a random integer in the [min, max] interval and print in to the console.
export function gen_random_int(min: number, max: number, description: string) {
  const min_int = Math.ceil(min);
  const max_int = Math.floor(max);
  const result =  Math.floor(Math.random() * (max_int - min_int + 1) + min_int);
  console.log(`Generated ${description}: ${result}`);

  return result;
}
