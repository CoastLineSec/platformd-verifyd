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

static SD_VARLINK_DEFINE_ENUM_TYPE(MessageStyle,
        SD_VARLINK_DEFINE_ENUM_VALUE(info),
        SD_VARLINK_DEFINE_ENUM_VALUE(error));

static SD_VARLINK_DEFINE_STRUCT_TYPE(VerificationMessage,
        SD_VARLINK_DEFINE_FIELD_BY_TYPE(style, MessageStyle, 0),
        SD_VARLINK_DEFINE_FIELD(text, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(VerificationResult,
        SD_VARLINK_DEFINE_FIELD(verified, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_FIELD(method, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(realtimeUSec, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(VerifyUserWithMessages, SD_VARLINK_REQUIRES_MORE,
        SD_VARLINK_DEFINE_INPUT(sessionId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(reason, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(message, VerificationMessage, SD_VARLINK_NULLABLE),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(result, VerificationResult, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(VerificationContext,
        SD_VARLINK_DEFINE_FIELD(challengeHex, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(audience, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(operationDigestHex, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(VerifyUserWithContext, SD_VARLINK_REQUIRES_MORE,
        SD_VARLINK_DEFINE_INPUT(sessionId, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT(reason, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_INPUT_BY_TYPE(context, VerificationContext, 0),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(message, VerificationMessage, SD_VARLINK_NULLABLE),
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(result, VerificationResult, SD_VARLINK_NULLABLE));

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
        &vl_type_MessageStyle,
        &vl_type_VerificationMessage,
        &vl_type_VerificationResult,
        &vl_method_VerifyUserWithMessages,
        &vl_type_VerificationContext,
        &vl_method_VerifyUserWithContext,
        &vl_error_PermissionDenied,
        &vl_error_VerificationUnsupported,
        &vl_error_VerificationTimedOut,
        &vl_error_VerificationCancelled,
        &vl_error_PromptUnavailable,
        &vl_error_NoSession,
        &vl_error_SessionNotEligible,
        &vl_error_AmbiguousSession,
        &vl_error_Busy);
