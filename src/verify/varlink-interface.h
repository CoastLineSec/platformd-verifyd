/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-varlink-idl.h>

static SD_VARLINK_DEFINE_METHOD(VerifyUser,
        SD_VARLINK_DEFINE_INPUT(sessionId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(reason, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(verified, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(method, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(realtimeUSec, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_ERROR(PermissionDenied);

static SD_VARLINK_DEFINE_ERROR(VerificationUnsupported);

static SD_VARLINK_DEFINE_ERROR(VerificationTimedOut);

static SD_VARLINK_DEFINE_ERROR(VerificationCancelled);

static SD_VARLINK_DEFINE_ERROR(PromptUnavailable);

static SD_VARLINK_DEFINE_ERROR(NoSession);

static SD_VARLINK_DEFINE_ERROR(SessionNotEligible);

static SD_VARLINK_DEFINE_ERROR(AmbiguousSession);

static SD_VARLINK_DEFINE_ERROR(Busy);

static SD_VARLINK_DEFINE_INTERFACE(io_platformd_Verify, "io.platformd.Verify",
        &vl_method_VerifyUser,
        &vl_error_PermissionDenied,
        &vl_error_VerificationUnsupported,
        &vl_error_VerificationTimedOut,
        &vl_error_VerificationCancelled,
        &vl_error_PromptUnavailable,
        &vl_error_NoSession,
        &vl_error_SessionNotEligible,
        &vl_error_AmbiguousSession,
        &vl_error_Busy);
