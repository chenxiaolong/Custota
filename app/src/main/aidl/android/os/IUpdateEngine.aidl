/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.os;

import android.os.IUpdateEngineCallback;
import android.os.ParcelFileDescriptor;

/** @hide */
interface IUpdateEngine {
  /** @hide */
  void applyPayload(String url,
                    in long payload_offset,
                    in long payload_size,
                    in String[] headerKeyValuePairs);
  /** @hide */
  void applyPayloadFd(in ParcelFileDescriptor pfd,
                      in long payload_offset,
                      in long payload_size,
                      in String[] headerKeyValuePairs);
  /** @hide */
  boolean bind(IUpdateEngineCallback callback);
  /** @hide */
  boolean unbind(IUpdateEngineCallback callback);
  /** @hide */
  void suspend();
  /** @hide */
  void resume();
  /** @hide */
  void cancel();
  /** @hide */
  void resetStatus();
  /** @hide */
  void setShouldSwitchSlotOnReboot(in String metadataFilename);
  /** @hide */
  void resetShouldSwitchSlotOnReboot();

  /** @hide */
  boolean verifyPayloadApplicable(in String metadataFilename);
  /**
   * Allocate space on userdata partition.
   *
   * @return 0 indicates allocation is successful.
   *   Non-zero indicates space is insufficient. The returned value is the
   *   total required space (in bytes) on userdata partition.
   *
   * @throws ServiceSpecificException for other errors.
   *
   * @hide
   */
  long allocateSpaceForPayload(in String metadataFilename,
                               in String[] headerKeyValuePairs);
  /** @hide
   *
   * Wait for merge to finish, and clean up necessary files.
   *
   * @param callback Report status updates in callback (not the one previously
   * bound with {@link #bind()}).
   * {@link IUpdateEngineCallback#onStatusUpdate} is called with
   * CLEANUP_PREVIOUS_UPDATE and a progress value during the cleanup.
   * {@link IUpdateEngineCallback#onPayloadApplicationComplete} is called at
   * the end with SUCCESS if successful. ERROR if transient errors (e.g. merged
   * but needs reboot). DEVICE_CORRUPTED for permanent errors.
   */
  void cleanupSuccessfulUpdate(IUpdateEngineCallback callback);
}
