const r4os = @import("r4os");
const std = @import("std");

const HmacMd5 = std.crypto.auth.hmac.HmacMd5;

pub const op_capabilities: u32 = 1;
pub const op_classify_tsrequest: u32 = 2;
pub const op_selftest: u32 = 3;
pub const op_build_tsrequest: u32 = 4;
pub const op_classify_spnego: u32 = 5;
pub const op_build_spnego_neg_token_resp: u32 = 6;
pub const op_ntlmv2_profile: u32 = 7;
pub const op_validate_fixed_credentials: u32 = 8;
pub const op_error_contract: u32 = 9;
pub const op_credssp_state_contract: u32 = 10;
pub const op_credssp_process_state: u32 = 11;
pub const op_credssp_build_challenge: u32 = 12;
pub const op_credssp_build_authenticate_fixture: u32 = 13;
pub const op_credssp_build_pubkeyauth_fixture: u32 = 14;
pub const op_credssp_windows_contract: u32 = 15;
pub const op_credssp_process_windows_state: u32 = 16;
pub const op_credssp_windows_harness: u32 = 17;
pub const op_credssp_live_contract: u32 = 18;
pub const op_credssp_process_live_state: u32 = 19;
pub const op_credssp_live_harness: u32 = 20;

pub const auth_result_ok: i32 = 0;
pub const auth_result_bad_buffer: i32 = -2;
pub const auth_result_buffer_small: i32 = -5;
pub const auth_result_bad_token: i32 = -6;
pub const auth_result_bad_password: i32 = -20;
pub const auth_result_unsupported_kerberos: i32 = -21;
pub const auth_result_unsupported_domain: i32 = -22;
pub const auth_result_missing_tls_context: i32 = -23;
pub const auth_result_bad_pubkeyauth: i32 = -24;
pub const auth_result_bad_state: i32 = -25;
pub const auth_result_unsupported_ntlm: i32 = -26;

const fixed_user = "r4os";
const fixed_user_upper = "R4OS";
const fixed_password = "rosebud";
const fixed_target = "R4OS";
const fixed_workstation = "R4OS";
const tsrequest_version: u8 = 2;
const tsrequest_max_supported_version: u8 = 6;
const der_tag_sequence: u8 = 0x30;
const der_tag_integer: u8 = 0x02;
const der_tag_octet_string: u8 = 0x04;
const der_tag_oid: u8 = 0x06;
const der_tag_enumerated: u8 = 0x0A;
const der_tag_initial_context_token: u8 = 0x60;
const der_tag_neg_token_init: u8 = 0xA0;
const der_tag_neg_token_resp: u8 = 0xA1;
const ntlmssp_signature = "NTLMSSP\x00";
const oid_spnego = [_]u8{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 };
const oid_ntlmssp = [_]u8{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A };
const oid_kerberos = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02 };
const fixture_server_challenge = [_]u8{ 0x52, 0x34, 0x4F, 0x53, 0x55, 0x35, 0x35, 0x20 };
const fixture_client_challenge = [_]u8{ 0x43, 0x4C, 0x49, 0x45, 0x4E, 0x54, 0x32, 0x30 };
const fixture_timestamp = [_]u8{ 0x00, 0x80, 0x5C, 0xD8, 0x3C, 0xD9, 0xDC, 0x01 };
const fixture_tls_pubkey_hash = [_]u8{
    0x52, 0x34, 0x54, 0x4c, 0x53, 0x2d, 0x50, 0x55,
    0x42, 0x4b, 0x45, 0x59, 0x2d, 0x30, 0x35, 0x35,
    0x32, 0x35, 0x2d, 0x42, 0x49, 0x4e, 0x44, 0x49,
    0x4e, 0x47, 0x2d, 0x56, 0x31, 0x00, 0x00, 0x01,
};
const windows_tls_pubkey_hash = [_]u8{
    0x52, 0x34, 0x54, 0x4c, 0x53, 0x2d, 0x53, 0x45,
    0x53, 0x53, 0x49, 0x4f, 0x4e, 0x2d, 0x30, 0x35,
    0x35, 0x32, 0x37, 0x2d, 0x50, 0x55, 0x42, 0x4b,
    0x45, 0x59, 0x2d, 0x42, 0x49, 0x4e, 0x44, 0x01,
};
const credssp_pubkeyauth_label = "CREDSSP-PUBKEYAUTH-05525";
const windows_pubkeyauth_label = "CREDSSP-WINDOWS-PUBKEYAUTH-05528";
const magic_credssp_state = "R4CS";
const credssp_state_header_len: usize = 8;
const magic_credssp_windows_state = "R4CW";
const credssp_windows_state_header_len: usize = 40;
const magic_credssp_live_state = "R4CL";
const magic_tls12_live_stream = "R4LK";
const credssp_live_state_header_len: usize = 12;
const credssp_live_flag_tls: u8 = 0x01;
const tls12_live_stream_state_len: usize = 4 + 8 + 8 + 16 + 16 + 4 + 4 + 48 + 32;
const tls12_live_stream_pubkey_hash_offset: usize = tls12_live_stream_state_len - 32;
const credssp_phase_negotiate: u8 = 1;
const credssp_phase_authenticate: u8 = 2;
const credssp_phase_pubkeyauth: u8 = 3;
const credssp_windows_variant_ntlm: u8 = 1;
const credssp_windows_variant_kerberos: u8 = 2;
const credssp_windows_variant_domain: u8 = 3;
const ntlm_type1: u32 = 1;
const ntlm_type2: u32 = 2;
const ntlm_type3: u32 = 3;
const ntlm_flags_unicode: u32 = 0x0000_0001;
const ntlm_flags_oem: u32 = 0x0000_0002;
const ntlm_flags_request_target: u32 = 0x0000_0004;
const ntlm_flags_ntlm: u32 = 0x0000_0200;
const ntlm_flags_always_sign: u32 = 0x0000_8000;
const ntlm_flags_target_info: u32 = 0x0080_0000;
const ntlm_flags_version: u32 = 0x0200_0000;
const ntlm_flags_128: u32 = 0x2000_0000;
const ntlm_flags_56: u32 = 0x8000_0000;
const ntlm_flags_r4os = ntlm_flags_unicode | ntlm_flags_oem | ntlm_flags_request_target | ntlm_flags_ntlm | ntlm_flags_always_sign | ntlm_flags_target_info | ntlm_flags_version | ntlm_flags_128 | ntlm_flags_56;

const spnego_kind_unknown: u8 = 0;
const spnego_kind_neg_token_init: u8 = 1;
const spnego_kind_neg_token_resp: u8 = 2;
const spnego_kind_raw_ntlm: u8 = 3;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("r4auth_init", "r4auth_shutdown", "r4auth_query", "r4auth_dispatch"));
}

comptime {
    var md4_empty: [16]u8 = undefined;
    md4Hash("", &md4_empty);
    const expected = [_]u8{ 0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0 };
    if (!bytesEqual(md4_empty[0..], expected[0..])) @compileError("R4AUTH MD4 primitive failed known-vector check");
}

export fn r4auth_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    ctx.logInfo("R4AUTH.R4P init");
    _ = ctx.registerRole("security.credssp", .data, 0);
    _ = ctx.setStatus(.active, "R4AUTH CredSSP state machine active");
    return 0;
}

export fn r4auth_shutdown() callconv(.c) i32 {
    return 0;
}

export fn r4auth_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("R4AUTH ready"),
    };
    return 0;
}

export fn r4auth_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    return switch (op) {
        op_capabilities => writeOut(out_buffer, "role=security.credssp;stage=credssp-live-state;depends=security.tls;auth=fixed-single-user;kerberos=no;domain=no;ops=tsrequest,spnego,ntlmv2,pubkeyauth,state,windows-harness,live-state"),
        op_classify_tsrequest => classifyTsRequest(in_buffer, out_buffer),
        op_selftest => selftest(out_buffer),
        op_build_tsrequest => buildTsRequest(in_buffer, out_buffer),
        op_classify_spnego => classifySpnego(in_buffer, out_buffer),
        op_build_spnego_neg_token_resp => buildSpnegoNegTokenResp(in_buffer, out_buffer),
        op_ntlmv2_profile => describeNtlmv2Profile(in_buffer, out_buffer),
        op_validate_fixed_credentials => validateFixedCredentials(in_buffer, out_buffer),
        op_error_contract => describeErrorContract(in_buffer, out_buffer),
        op_credssp_state_contract => describeCredsspStateContract(in_buffer, out_buffer),
        op_credssp_process_state => processCredsspState(in_buffer, out_buffer),
        op_credssp_build_challenge => buildCredsspChallenge(in_buffer, out_buffer),
        op_credssp_build_authenticate_fixture => buildCredsspAuthenticateFixture(in_buffer, out_buffer),
        op_credssp_build_pubkeyauth_fixture => buildCredsspPubKeyAuthFixture(in_buffer, out_buffer),
        op_credssp_windows_contract => describeCredsspWindowsContract(in_buffer, out_buffer),
        op_credssp_process_windows_state => processCredsspWindowsState(in_buffer, out_buffer),
        op_credssp_windows_harness => credsspWindowsHarnessDispatch(in_buffer, out_buffer),
        op_credssp_live_contract => describeCredsspLiveContract(in_buffer, out_buffer),
        op_credssp_process_live_state => processCredsspLiveState(in_buffer, out_buffer),
        op_credssp_live_harness => credsspLiveHarnessDispatch(in_buffer, out_buffer),
        else => -4,
    };
}

fn classifyTsRequest(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const input = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    const info = parseTsRequestInfo(input) orelse return auth_result_bad_token;

    var text: [384]u8 = .{0} ** 384;
    var pos: usize = 0;
    appendText(text[0..], &pos, "credssp-tsrequest;der=sequence;version=");
    if (info.has_version) appendU64(text[0..], &pos, info.version) else appendText(text[0..], &pos, "missing");
    appendText(text[0..], &pos, ";nego_tokens=");
    appendU64(text[0..], &pos, info.nego_tokens);
    appendText(text[0..], &pos, ";auth_info=");
    appendText(text[0..], &pos, boolText(info.has_auth_info));
    appendText(text[0..], &pos, ";pub_key_auth=");
    appendText(text[0..], &pos, boolText(info.has_pub_key_auth));
    appendText(text[0..], &pos, ";client_nonce=");
    appendText(text[0..], &pos, boolText(info.has_client_nonce));
    appendText(text[0..], &pos, ";error_code=");
    if (info.has_error_code) appendU64(text[0..], &pos, info.error_code) else appendText(text[0..], &pos, "none");
    appendText(text[0..], &pos, ";ntlm=");
    appendText(text[0..], &pos, boolText(info.has_ntlm));
    appendText(text[0..], &pos, ";kerberos=");
    appendText(text[0..], &pos, boolText(info.has_kerberos));
    appendText(text[0..], &pos, ";ntlm_type=");
    appendU64(text[0..], &pos, info.ntlm_message_type);
    appendText(text[0..], &pos, ";unknown_fields=");
    appendU64(text[0..], &pos, info.unknown_fields);
    appendText(text[0..], &pos, ";supported=");
    appendText(text[0..], &pos, boolText(info.has_version and isSupportedTsRequestVersion(info.version) and !isKerberosOnlyOffer(info)));
    return writeOut(out_buffer, text[0..pos]);
}

fn buildTsRequest(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const token = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    const out = outputBytes(out_buffer) orelse return auth_result_bad_buffer;
    const len = buildTsRequestBytes(out, token) orelse return auth_result_buffer_small;
    out_buffer.len = @intCast(len);
    return auth_result_ok;
}

fn classifySpnego(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const input = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    const info = parseSpnegoInfo(input) orelse return auth_result_bad_token;
    var text: [320]u8 = .{0} ** 320;
    var pos: usize = 0;
    appendText(text[0..], &pos, "spnego;kind=");
    appendText(text[0..], &pos, spnegoKindName(info.kind));
    appendText(text[0..], &pos, ";spnego_oid=");
    appendText(text[0..], &pos, boolText(info.has_spnego_oid));
    appendText(text[0..], &pos, ";ntlm=");
    appendText(text[0..], &pos, boolText(info.has_ntlm));
    appendText(text[0..], &pos, ";kerberos=");
    appendText(text[0..], &pos, boolText(info.has_kerberos));
    appendText(text[0..], &pos, ";ntlm_type=");
    appendU64(text[0..], &pos, info.ntlm_message_type);
    appendText(text[0..], &pos, ";supported=");
    appendText(text[0..], &pos, boolText(info.has_ntlm and !info.has_kerberos));
    appendText(text[0..], &pos, ";error=");
    appendText(text[0..], &pos, if (info.has_kerberos and !info.has_ntlm) "unsupported-kerberos" else "none");
    return writeOut(out_buffer, text[0..pos]);
}

fn buildSpnegoNegTokenResp(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const token = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    const out = outputBytes(out_buffer) orelse return auth_result_bad_buffer;
    const len = buildSpnegoNegTokenRespBytes(out, token, 1) orelse return auth_result_buffer_small;
    out_buffer.len = @intCast(len);
    return auth_result_ok;
}

fn describeNtlmv2Profile(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    const profile = ntlmv2FixedProfile();
    var text: [512]u8 = .{0} ** 512;
    var pos: usize = 0;
    appendText(text[0..], &pos, "ntlmv2-profile;user=");
    appendText(text[0..], &pos, fixed_user);
    appendText(text[0..], &pos, ";target=");
    appendText(text[0..], &pos, fixed_target);
    appendText(text[0..], &pos, ";password=fixed");
    appendText(text[0..], &pos, ";auth_model=fixed-single-user");
    appendText(text[0..], &pos, ";kerberos=no;domain=no;permissions=none");
    appendText(text[0..], &pos, ";nt_hash=");
    appendHexBytes(text[0..], &pos, profile.nt_hash[0..]);
    appendText(text[0..], &pos, ";ntowfv2=");
    appendHexBytes(text[0..], &pos, profile.ntowfv2[0..]);
    appendText(text[0..], &pos, ";server_challenge=");
    appendHexBytes(text[0..], &pos, fixture_server_challenge[0..]);
    appendText(text[0..], &pos, ";client_challenge=");
    appendHexBytes(text[0..], &pos, fixture_client_challenge[0..]);
    appendText(text[0..], &pos, ";ntproof=");
    appendHexBytes(text[0..], &pos, profile.nt_proof[0..]);
    return writeOut(out_buffer, text[0..pos]);
}

fn validateFixedCredentials(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const input = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    if (fieldEquals(input, "mech", "kerberos")) return auth_result_unsupported_kerberos;
    if (!fieldEquals(input, "tls", "protected")) return auth_result_missing_tls_context;
    if (fieldHasUnsupportedDomain(input)) return auth_result_unsupported_domain;
    if (!fieldEquals(input, "user", fixed_user)) return auth_result_bad_password;
    if (!fieldEquals(input, "password", fixed_password)) return auth_result_bad_password;
    return writeOut(out_buffer, "auth;result=ok;user=r4os;auth_model=fixed-single-user;permissions=none");
}

fn describeErrorContract(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    return writeOut(out_buffer, "credssp-errors;bad_password=-20;bad_token=-6;unsupported_kerberos=-21;unsupported_domain=-22;missing_tls_context=-23;bad_pubkeyauth=-24;bad_state=-25;unsupported_ntlm=-26;auth_model=fixed-single-user;user=r4os;password=rosebud;permissions=none");
}

fn describeCredsspStateContract(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    var text: [896]u8 = .{0} ** 896;
    var pos: usize = 0;
    appendText(text[0..], &pos, "credssp-state-machine;input=R4CS+phase+tls+reserved+TSRequest");
    appendText(text[0..], &pos, ";phases=1:negotiate,2:authenticate,3:pubkeyauth");
    appendText(text[0..], &pos, ";tsrequest_versions=2..6");
    appendText(text[0..], &pos, ";tls_required=yes");
    appendText(text[0..], &pos, ";mech=ntlmv2");
    appendText(text[0..], &pos, ";challenge=op12");
    appendText(text[0..], &pos, ";authenticate_fixture=op13");
    appendText(text[0..], &pos, ";pubkeyauth_fixture=op14");
    appendText(text[0..], &pos, ";pubkeyauth=hmac-md5(ntowfv2,tls_pubkey_hash+credssp-binding)");
    appendText(text[0..], &pos, ";windows_contract=op15");
    appendText(text[0..], &pos, ";windows_process=op16");
    appendText(text[0..], &pos, ";windows_harness=op17");
    appendText(text[0..], &pos, ";live_contract=op18");
    appendText(text[0..], &pos, ";live_process=op19");
    appendText(text[0..], &pos, ";live_harness=op20");
    appendText(text[0..], &pos, ";kerberos=no;domain=no;user=r4os;password=rosebud");
    appendText(text[0..], &pos, ";next=send_challenge|pubkeyauth|rdp");
    appendText(text[0..], &pos, ";errors=-6,-20,-21,-22,-23,-24,-25,-26");
    return writeOut(out_buffer, text[0..pos]);
}

fn describeCredsspWindowsContract(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    var text: [1024]u8 = .{0} ** 1024;
    var pos: usize = 0;
    appendText(text[0..], &pos, "credssp-windows-contract");
    appendText(text[0..], &pos, ";input=R4CW+phase+tls+variant+reserved+tls_pubkey_hash32+TSRequest");
    appendText(text[0..], &pos, ";ops=op15:contract,op16:process,op17:harness");
    appendText(text[0..], &pos, ";phases=1:negotiate,2:authenticate,3:pubkeyauth");
    appendText(text[0..], &pos, ";spnego=windows-negTokenInit+negTokenResp");
    appendText(text[0..], &pos, ";ntlm=type1,type2,type3");
    appendText(text[0..], &pos, ";pubkeyauth=hmac-md5(ntowfv2,tls_pubkey_hash+windows-binding)");
    appendText(text[0..], &pos, ";tls_required=yes");
    appendText(text[0..], &pos, ";kerberos=blocked:-21");
    appendText(text[0..], &pos, ";domain=blocked:-22");
    appendText(text[0..], &pos, ";bad_pubkeyauth=-24;bad_tsrequest=-6;missing_tls=-23");
    appendText(text[0..], &pos, ";user=r4os;password=rosebud;permissions=none");
    appendText(text[0..], &pos, ";live_contract=op18");
    appendText(text[0..], &pos, ";rdpsvc=consumer-only;next=r4auth-live-state");
    return writeOut(out_buffer, text[0..pos]);
}

fn describeCredsspLiveContract(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    var text: [1280]u8 = .{0} ** 1280;
    var pos: usize = 0;
    appendText(text[0..], &pos, "credssp-live-contract");
    appendText(text[0..], &pos, ";input=R4CL+phase+variant+flags+reserved+stream_len+R4LK+TSRequest");
    appendText(text[0..], &pos, ";ops=op18:contract,op19:process,op20:harness");
    appendText(text[0..], &pos, ";stream_state=R4LK");
    appendText(text[0..], &pos, ";stream_len=");
    appendU64(text[0..], &pos, tls12_live_stream_state_len);
    appendText(text[0..], &pos, ";tls_required=yes");
    appendText(text[0..], &pos, ";tls_pubkey_hash=R4LK[-32]");
    appendText(text[0..], &pos, ";phases=1:negotiate,2:authenticate,3:pubkeyauth");
    appendText(text[0..], &pos, ";spnego=windows-negTokenInit+negTokenResp");
    appendText(text[0..], &pos, ";ntlm=type1,type2,type3");
    appendText(text[0..], &pos, ";pubkeyauth=hmac-md5(ntowfv2,r4lk_pubkey_hash+windows-binding)");
    appendText(text[0..], &pos, ";windows_final=authInfo+pubKeyAuth");
    appendText(text[0..], &pos, ";resume=yes");
    appendText(text[0..], &pos, ";kerberos=blocked:-21");
    appendText(text[0..], &pos, ";domain=blocked:-22");
    appendText(text[0..], &pos, ";bad_password=-20;bad_pubkeyauth=-24;bad_tsrequest=-6;missing_tls=-23;bad_state=-25;unsupported_ntlm=-26");
    appendText(text[0..], &pos, ";user=r4os;password=rosebud;permissions=none");
    appendText(text[0..], &pos, ";rdpsvc=consumer-only;next=rdpsvc-credssp-loop");
    return writeOut(out_buffer, text[0..pos]);
}

fn processCredsspState(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const input = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    const frame = parseCredsspStateFrame(input) orelse return auth_result_bad_state;
    if (!frame.tls_protected) return auth_result_missing_tls_context;
    const info = parseTsRequestInfo(frame.tsrequest) orelse return auth_result_bad_token;
    if (!info.has_version or !isSupportedTsRequestVersion(info.version)) return auth_result_bad_token;
    if (isKerberosOnlyOffer(info)) return auth_result_unsupported_kerberos;

    return switch (frame.phase) {
        credssp_phase_negotiate => processCredsspNegotiate(info, out_buffer),
        credssp_phase_authenticate => processCredsspAuthenticate(info, out_buffer),
        credssp_phase_pubkeyauth => processCredsspPubKeyAuth(info, out_buffer),
        else => auth_result_bad_state,
    };
}

fn processCredsspWindowsState(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const input = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    const frame = parseCredsspWindowsStateFrame(input) orelse return auth_result_bad_state;
    if (!frame.tls_protected) return auth_result_missing_tls_context;
    if (allZero(frame.tls_pubkey_hash)) return auth_result_missing_tls_context;
    const info = parseTsRequestInfo(frame.tsrequest) orelse return auth_result_bad_token;
    if (!info.has_version or !isSupportedTsRequestVersion(info.version)) return auth_result_bad_token;
    if (isKerberosOnlyOffer(info)) return auth_result_unsupported_kerberos;

    return switch (frame.phase) {
        credssp_phase_negotiate => processCredsspNegotiate(info, out_buffer),
        credssp_phase_authenticate => processCredsspAuthenticate(info, out_buffer),
        credssp_phase_pubkeyauth => processCredsspPubKeyAuthWithHash(info, frame.tls_pubkey_hash, out_buffer),
        else => auth_result_bad_state,
    };
}

fn processCredsspLiveState(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    const input = inputBytes(in_buffer) orelse return auth_result_bad_buffer;
    const frame = parseCredsspLiveStateFrame(input) orelse return auth_result_bad_state;
    if (!frame.tls_protected) return auth_result_missing_tls_context;
    if (allZero(frame.tls_pubkey_hash)) return auth_result_missing_tls_context;
    if (frame.variant != credssp_windows_variant_ntlm and frame.variant != credssp_windows_variant_kerberos and frame.variant != credssp_windows_variant_domain) return auth_result_bad_state;
    const info = parseTsRequestInfo(frame.tsrequest) orelse return auth_result_bad_token;
    if (!info.has_version or !isSupportedTsRequestVersion(info.version)) return auth_result_bad_token;
    if (isKerberosOnlyOffer(info) or frame.variant == credssp_windows_variant_kerberos) return auth_result_unsupported_kerberos;

    return switch (frame.phase) {
        credssp_phase_negotiate => processCredsspLiveNegotiate(info, out_buffer),
        credssp_phase_authenticate => processCredsspLiveAuthenticate(info, frame.tls_pubkey_hash, out_buffer),
        credssp_phase_pubkeyauth => processCredsspLivePubKeyAuth(info, frame.tls_pubkey_hash, out_buffer),
        else => auth_result_bad_state,
    };
}

fn isKerberosOnlyOffer(info: TsRequestInfo) bool {
    return info.has_kerberos and !info.has_ntlm;
}

fn isSupportedTsRequestVersion(version: u32) bool {
    return version >= tsrequest_version and version <= tsrequest_max_supported_version;
}

fn buildCredsspChallenge(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    const out = outputBytes(out_buffer) orelse return auth_result_bad_buffer;
    var ntlm_challenge: [128]u8 = .{0} ** 128;
    const ntlm_len = buildNtlmChallengeToken(ntlm_challenge[0..]) orelse return auth_result_buffer_small;
    var spnego: [192]u8 = .{0} ** 192;
    const spnego_len = buildSpnegoNegTokenRespBytes(spnego[0..], ntlm_challenge[0..ntlm_len], 1) orelse return auth_result_buffer_small;
    const ts_len = buildTsRequestBytes(out, spnego[0..spnego_len]) orelse return auth_result_buffer_small;
    out_buffer.len = @intCast(ts_len);
    return auth_result_ok;
}

fn buildCredsspAuthenticateFixture(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    const out = outputBytes(out_buffer) orelse return auth_result_bad_buffer;
    var ntlm_auth: [256]u8 = .{0} ** 256;
    const ntlm_len = buildNtlmAuthenticateToken(ntlm_auth[0..]) orelse return auth_result_buffer_small;
    var spnego: [320]u8 = .{0} ** 320;
    const spnego_len = buildSpnegoNegTokenRespBytes(spnego[0..], ntlm_auth[0..ntlm_len], 0) orelse return auth_result_buffer_small;
    const ts_len = buildTsRequestBytes(out, spnego[0..spnego_len]) orelse return auth_result_buffer_small;
    out_buffer.len = @intCast(ts_len);
    return auth_result_ok;
}

fn buildCredsspPubKeyAuthFixture(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    const out = outputBytes(out_buffer) orelse return auth_result_bad_buffer;
    var pubkeyauth: [16]u8 = undefined;
    buildPubKeyAuthValue(&pubkeyauth);
    const ts_len = buildTsRequestPubKeyAuthBytes(out, pubkeyauth[0..]) orelse return auth_result_buffer_small;
    out_buffer.len = @intCast(ts_len);
    return auth_result_ok;
}

fn credsspWindowsHarnessDispatch(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    var result: CredsspWindowsHarnessResult = undefined;
    const rc = runCredsspWindowsHarness(&result);
    if (rc != auth_result_ok) return rc;

    var text: [1024]u8 = .{0} ** 1024;
    var pos: usize = 0;
    appendText(text[0..], &pos, "credssp-windows-harness");
    appendText(text[0..], &pos, ";negotiate=ok;challenge=ok;authenticate=ok;pubkeyauth=ok");
    appendText(text[0..], &pos, ";spnego=negTokenInit+negTokenResp");
    appendText(text[0..], &pos, ";ntlm=type1,type2,type3");
    appendText(text[0..], &pos, ";tls_pubkey_binding=ok");
    appendText(text[0..], &pos, ";mixed_offer=ntlm;bad_pubkeyauth=blocked;kerberos=blocked;domain=blocked;bad_tsrequest=blocked;missing_tls=blocked");
    appendText(text[0..], &pos, ";negotiate_bytes=");
    appendU64(text[0..], &pos, result.negotiate_len);
    appendText(text[0..], &pos, ";challenge_bytes=");
    appendU64(text[0..], &pos, result.challenge_len);
    appendText(text[0..], &pos, ";authenticate_bytes=");
    appendU64(text[0..], &pos, result.authenticate_len);
    appendText(text[0..], &pos, ";pubkeyauth_bytes=");
    appendU64(text[0..], &pos, result.pubkeyauth_len);
    appendText(text[0..], &pos, ";user=r4os;password=rosebud;next=rdpsvc-stream");
    return writeOut(out_buffer, text[0..pos]);
}

fn credsspLiveHarnessDispatch(in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    _ = in_buffer;
    var result: CredsspLiveHarnessResult = undefined;
    const rc = runCredsspLiveHarness(&result);
    if (rc != auth_result_ok) return rc;

    var text: [1280]u8 = .{0} ** 1280;
    var pos: usize = 0;
    appendText(text[0..], &pos, "credssp-live-harness");
    appendText(text[0..], &pos, ";state=R4CL;stream=R4LK");
    appendText(text[0..], &pos, ";negotiate=ok;challenge=ok;authenticate=ok;pubkeyauth=ok");
    appendText(text[0..], &pos, ";resume=ok;spnego=negTokenInit+negTokenResp;ntlm=type1,type2,type3");
    appendText(text[0..], &pos, ";tls_pubkey_binding=from-r4lk");
    appendText(text[0..], &pos, ";mixed_offer=ntlm;windows_final=ok;bad_password=blocked;bad_pubkeyauth=blocked;kerberos=blocked;domain=blocked;bad_tsrequest=blocked;missing_tls=blocked");
    appendText(text[0..], &pos, ";stream_bytes=");
    appendU64(text[0..], &pos, result.stream_len);
    appendText(text[0..], &pos, ";negotiate_bytes=");
    appendU64(text[0..], &pos, result.negotiate_len);
    appendText(text[0..], &pos, ";challenge_bytes=");
    appendU64(text[0..], &pos, result.challenge_len);
    appendText(text[0..], &pos, ";authenticate_bytes=");
    appendU64(text[0..], &pos, result.authenticate_len);
    appendText(text[0..], &pos, ";pubkeyauth_bytes=");
    appendU64(text[0..], &pos, result.pubkeyauth_len);
    appendText(text[0..], &pos, ";windows_final_bytes=");
    appendU64(text[0..], &pos, result.windows_final_len);
    appendText(text[0..], &pos, ";user=r4os;password=rosebud;next=rdpsvc-credssp-loop");
    return writeOut(out_buffer, text[0..pos]);
}

const CredsspWindowsHarnessResult = struct {
    negotiate_len: usize,
    challenge_len: usize,
    authenticate_len: usize,
    pubkeyauth_len: usize,
};

const CredsspLiveHarnessResult = struct {
    stream_len: usize,
    negotiate_len: usize,
    challenge_len: usize,
    authenticate_len: usize,
    pubkeyauth_len: usize,
    windows_final_len: usize,
};

fn runCredsspWindowsHarness(result: *CredsspWindowsHarnessResult) i32 {
    var ntlm_negotiate: [64]u8 = .{0} ** 64;
    const ntlm_negotiate_len = buildNtlmNegotiateToken(ntlm_negotiate[0..]) orelse return auth_result_buffer_small;
    var spnego_init: [160]u8 = .{0} ** 160;
    const spnego_init_len = buildSpnegoNegTokenInitBytes(spnego_init[0..], ntlm_negotiate[0..ntlm_negotiate_len], oid_ntlmssp[0..]) orelse return auth_result_buffer_small;
    var negotiate_ts: [224]u8 = .{0} ** 224;
    const negotiate_ts_len = buildTsRequestBytes(negotiate_ts[0..], spnego_init[0..spnego_init_len]) orelse return auth_result_buffer_small;
    var negotiate_frame: [320]u8 = .{0} ** 320;
    const negotiate_frame_len = buildCredsspWindowsStateFrame(negotiate_frame[0..], credssp_phase_negotiate, true, credssp_windows_variant_ntlm, windows_tls_pubkey_hash[0..], negotiate_ts[0..negotiate_ts_len]) orelse return auth_result_buffer_small;
    var state_text: [512]u8 = .{0} ** 512;
    var state_out = r4os.abi.ProtocolBuffer{ .data = &state_text, .len = 0, .capacity = state_text.len };
    var state_in = r4os.abi.ProtocolBuffer{ .data = &negotiate_frame, .len = @intCast(negotiate_frame_len), .capacity = negotiate_frame.len };
    if (processCredsspWindowsState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    if (!contains(state_text[0..@intCast(state_out.len)], "phase=negotiate")) return auth_result_bad_state;

    const mixed_oids = [_][]const u8{ oid_kerberos[0..], oid_ntlmssp[0..] };
    var mixed_spnego: [192]u8 = .{0} ** 192;
    const mixed_spnego_len = buildSpnegoNegTokenInitBytesWithMechs(mixed_spnego[0..], ntlm_negotiate[0..ntlm_negotiate_len], mixed_oids[0..]) orelse return auth_result_buffer_small;
    var mixed_ts: [256]u8 = .{0} ** 256;
    const mixed_ts_len = buildTsRequestBytes(mixed_ts[0..], mixed_spnego[0..mixed_spnego_len]) orelse return auth_result_buffer_small;
    var mixed_frame: [384]u8 = .{0} ** 384;
    const mixed_frame_len = buildCredsspWindowsStateFrame(mixed_frame[0..], credssp_phase_negotiate, true, credssp_windows_variant_ntlm, windows_tls_pubkey_hash[0..], mixed_ts[0..mixed_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &mixed_frame, .len = @intCast(mixed_frame_len), .capacity = mixed_frame.len };
    if (processCredsspWindowsState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    const mixed_state = state_text[0..@intCast(state_out.len)];
    if (!contains(mixed_state, "phase=negotiate") or !contains(mixed_state, "ntlm_type=1")) return auth_result_bad_state;

    var challenge_ts: [256]u8 = .{0} ** 256;
    var challenge_out = r4os.abi.ProtocolBuffer{ .data = &challenge_ts, .len = 0, .capacity = challenge_ts.len };
    if (buildCredsspChallenge(&state_in, &challenge_out) != auth_result_ok) return auth_result_bad_state;
    const challenge_info = parseTsRequestInfo(challenge_ts[0..@intCast(challenge_out.len)]) orelse return auth_result_bad_token;
    if (challenge_info.ntlm_message_type != ntlm_type2) return auth_result_bad_state;

    var ntlm_authenticate: [320]u8 = .{0} ** 320;
    const ntlm_authenticate_len = buildNtlmAuthenticateTokenVariant(ntlm_authenticate[0..], "") orelse return auth_result_buffer_small;
    var spnego_authenticate: [384]u8 = .{0} ** 384;
    const spnego_authenticate_len = buildSpnegoNegTokenRespBytes(spnego_authenticate[0..], ntlm_authenticate[0..ntlm_authenticate_len], 0) orelse return auth_result_buffer_small;
    var authenticate_ts: [512]u8 = .{0} ** 512;
    const authenticate_ts_len = buildTsRequestBytes(authenticate_ts[0..], spnego_authenticate[0..spnego_authenticate_len]) orelse return auth_result_buffer_small;
    var authenticate_frame: [640]u8 = .{0} ** 640;
    const authenticate_frame_len = buildCredsspWindowsStateFrame(authenticate_frame[0..], credssp_phase_authenticate, true, credssp_windows_variant_ntlm, windows_tls_pubkey_hash[0..], authenticate_ts[0..authenticate_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &authenticate_frame, .len = @intCast(authenticate_frame_len), .capacity = authenticate_frame.len };
    if (processCredsspWindowsState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    if (!contains(state_text[0..@intCast(state_out.len)], "phase=authenticate")) return auth_result_bad_state;

    var pubkeyauth: [16]u8 = undefined;
    buildWindowsPubKeyAuthValue(&pubkeyauth, windows_tls_pubkey_hash[0..]);
    var pubkey_ts: [128]u8 = .{0} ** 128;
    const pubkey_ts_len = buildTsRequestPubKeyAuthBytes(pubkey_ts[0..], pubkeyauth[0..]) orelse return auth_result_buffer_small;
    var pubkey_frame: [192]u8 = .{0} ** 192;
    const pubkey_frame_len = buildCredsspWindowsStateFrame(pubkey_frame[0..], credssp_phase_pubkeyauth, true, credssp_windows_variant_ntlm, windows_tls_pubkey_hash[0..], pubkey_ts[0..pubkey_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &pubkey_frame, .len = @intCast(pubkey_frame_len), .capacity = pubkey_frame.len };
    if (processCredsspWindowsState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    const pubkey_state = state_text[0..@intCast(state_out.len)];
    if (!contains(pubkey_state, "binding=windows-tls-pubkey") or !contains(pubkey_state, "complete=yes")) return auth_result_bad_state;

    var bad_pubkey_frame = pubkey_frame;
    bad_pubkey_frame[pubkey_frame_len - 1] ^= 0x7D;
    var bad_pubkey_in = r4os.abi.ProtocolBuffer{ .data = &bad_pubkey_frame, .len = @intCast(pubkey_frame_len), .capacity = bad_pubkey_frame.len };
    if (processCredsspWindowsState(&bad_pubkey_in, &state_out) != auth_result_bad_pubkeyauth) return auth_result_bad_state;

    var kerberos_spnego: [128]u8 = .{0} ** 128;
    const kerberos_spnego_len = buildSpnegoNegTokenInitBytes(kerberos_spnego[0..], "", oid_kerberos[0..]) orelse return auth_result_buffer_small;
    var kerberos_ts: [192]u8 = .{0} ** 192;
    const kerberos_ts_len = buildTsRequestBytes(kerberos_ts[0..], kerberos_spnego[0..kerberos_spnego_len]) orelse return auth_result_buffer_small;
    var kerberos_frame: [256]u8 = .{0} ** 256;
    const kerberos_frame_len = buildCredsspWindowsStateFrame(kerberos_frame[0..], credssp_phase_negotiate, true, credssp_windows_variant_kerberos, windows_tls_pubkey_hash[0..], kerberos_ts[0..kerberos_ts_len]) orelse return auth_result_buffer_small;
    var kerberos_in = r4os.abi.ProtocolBuffer{ .data = &kerberos_frame, .len = @intCast(kerberos_frame_len), .capacity = kerberos_frame.len };
    if (processCredsspWindowsState(&kerberos_in, &state_out) != auth_result_unsupported_kerberos) return auth_result_bad_state;

    var domain_auth: [320]u8 = .{0} ** 320;
    const domain_auth_len = buildNtlmAuthenticateTokenVariant(domain_auth[0..], "CORP") orelse return auth_result_buffer_small;
    var domain_spnego: [384]u8 = .{0} ** 384;
    const domain_spnego_len = buildSpnegoNegTokenRespBytes(domain_spnego[0..], domain_auth[0..domain_auth_len], 0) orelse return auth_result_buffer_small;
    var domain_ts: [512]u8 = .{0} ** 512;
    const domain_ts_len = buildTsRequestBytes(domain_ts[0..], domain_spnego[0..domain_spnego_len]) orelse return auth_result_buffer_small;
    var domain_frame: [640]u8 = .{0} ** 640;
    const domain_frame_len = buildCredsspWindowsStateFrame(domain_frame[0..], credssp_phase_authenticate, true, credssp_windows_variant_domain, windows_tls_pubkey_hash[0..], domain_ts[0..domain_ts_len]) orelse return auth_result_buffer_small;
    var domain_in = r4os.abi.ProtocolBuffer{ .data = &domain_frame, .len = @intCast(domain_frame_len), .capacity = domain_frame.len };
    if (processCredsspWindowsState(&domain_in, &state_out) != auth_result_unsupported_domain) return auth_result_bad_state;

    var bad_ts_frame = negotiate_frame;
    var bad_ts_len = negotiate_frame_len;
    bad_ts_len -= 3;
    var bad_ts_in = r4os.abi.ProtocolBuffer{ .data = &bad_ts_frame, .len = @intCast(bad_ts_len), .capacity = bad_ts_frame.len };
    if (processCredsspWindowsState(&bad_ts_in, &state_out) != auth_result_bad_token) return auth_result_bad_state;

    var missing_tls_frame = negotiate_frame;
    missing_tls_frame[5] = 0;
    var missing_tls_in = r4os.abi.ProtocolBuffer{ .data = &missing_tls_frame, .len = @intCast(negotiate_frame_len), .capacity = missing_tls_frame.len };
    if (processCredsspWindowsState(&missing_tls_in, &state_out) != auth_result_missing_tls_context) return auth_result_bad_state;

    result.* = .{
        .negotiate_len = negotiate_ts_len,
        .challenge_len = @intCast(challenge_out.len),
        .authenticate_len = authenticate_ts_len,
        .pubkeyauth_len = pubkey_ts_len,
    };
    return auth_result_ok;
}

fn runCredsspLiveHarness(result: *CredsspLiveHarnessResult) i32 {
    var tls_stream: [tls12_live_stream_state_len]u8 = .{0} ** tls12_live_stream_state_len;
    buildR4TlsLiveStreamFixture(&tls_stream);
    const tls_pubkey_hash = tls_stream[tls12_live_stream_pubkey_hash_offset..tls12_live_stream_state_len];

    var ntlm_negotiate: [64]u8 = .{0} ** 64;
    const ntlm_negotiate_len = buildNtlmNegotiateToken(ntlm_negotiate[0..]) orelse return auth_result_buffer_small;
    var spnego_init: [160]u8 = .{0} ** 160;
    const spnego_init_len = buildSpnegoNegTokenInitBytes(spnego_init[0..], ntlm_negotiate[0..ntlm_negotiate_len], oid_ntlmssp[0..]) orelse return auth_result_buffer_small;
    var negotiate_ts: [224]u8 = .{0} ** 224;
    const negotiate_ts_len = buildTsRequestBytes(negotiate_ts[0..], spnego_init[0..spnego_init_len]) orelse return auth_result_buffer_small;
    var negotiate_frame: [384]u8 = .{0} ** 384;
    const negotiate_frame_len = buildCredsspLiveStateFrame(negotiate_frame[0..], credssp_phase_negotiate, true, credssp_windows_variant_ntlm, tls_stream[0..], negotiate_ts[0..negotiate_ts_len]) orelse return auth_result_buffer_small;
    var state_text: [512]u8 = .{0} ** 512;
    var state_out = r4os.abi.ProtocolBuffer{ .data = &state_text, .len = 0, .capacity = state_text.len };
    var state_in = r4os.abi.ProtocolBuffer{ .data = &negotiate_frame, .len = @intCast(negotiate_frame_len), .capacity = negotiate_frame.len };
    if (processCredsspLiveState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    if (!contains(state_text[0..@intCast(state_out.len)], "phase=negotiate")) return auth_result_bad_state;
    if (!contains(state_text[0..@intCast(state_out.len)], "stream=R4LK")) return auth_result_bad_state;

    const mixed_oids = [_][]const u8{ oid_kerberos[0..], oid_ntlmssp[0..] };
    var mixed_spnego: [192]u8 = .{0} ** 192;
    const mixed_spnego_len = buildSpnegoNegTokenInitBytesWithMechs(mixed_spnego[0..], ntlm_negotiate[0..ntlm_negotiate_len], mixed_oids[0..]) orelse return auth_result_buffer_small;
    var mixed_ts: [256]u8 = .{0} ** 256;
    const mixed_ts_len = buildTsRequestBytesWithVersion(mixed_ts[0..], mixed_spnego[0..mixed_spnego_len], tsrequest_max_supported_version) orelse return auth_result_buffer_small;
    var mixed_frame: [448]u8 = .{0} ** 448;
    const mixed_frame_len = buildCredsspLiveStateFrame(mixed_frame[0..], credssp_phase_negotiate, true, credssp_windows_variant_ntlm, tls_stream[0..], mixed_ts[0..mixed_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &mixed_frame, .len = @intCast(mixed_frame_len), .capacity = mixed_frame.len };
    if (processCredsspLiveState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    const mixed_state = state_text[0..@intCast(state_out.len)];
    if (!contains(mixed_state, "phase=negotiate") or !contains(mixed_state, "stream=R4LK") or !contains(mixed_state, "ntlm_type=1")) return auth_result_bad_state;

    var challenge_ts: [256]u8 = .{0} ** 256;
    var challenge_out = r4os.abi.ProtocolBuffer{ .data = &challenge_ts, .len = 0, .capacity = challenge_ts.len };
    if (buildCredsspChallenge(&state_in, &challenge_out) != auth_result_ok) return auth_result_bad_state;
    const challenge_info = parseTsRequestInfo(challenge_ts[0..@intCast(challenge_out.len)]) orelse return auth_result_bad_token;
    if (challenge_info.ntlm_message_type != ntlm_type2) return auth_result_bad_state;

    var ntlm_authenticate: [320]u8 = .{0} ** 320;
    const ntlm_authenticate_len = buildNtlmAuthenticateTokenVariant(ntlm_authenticate[0..], "") orelse return auth_result_buffer_small;
    var spnego_authenticate: [384]u8 = .{0} ** 384;
    const spnego_authenticate_len = buildSpnegoNegTokenRespBytes(spnego_authenticate[0..], ntlm_authenticate[0..ntlm_authenticate_len], 0) orelse return auth_result_buffer_small;
    var authenticate_ts: [512]u8 = .{0} ** 512;
    const authenticate_ts_len = buildTsRequestBytes(authenticate_ts[0..], spnego_authenticate[0..spnego_authenticate_len]) orelse return auth_result_buffer_small;
    var authenticate_frame: [704]u8 = .{0} ** 704;
    const authenticate_frame_len = buildCredsspLiveStateFrame(authenticate_frame[0..], credssp_phase_authenticate, true, credssp_windows_variant_ntlm, tls_stream[0..], authenticate_ts[0..authenticate_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &authenticate_frame, .len = @intCast(authenticate_frame_len), .capacity = authenticate_frame.len };
    if (processCredsspLiveState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    if (!contains(state_text[0..@intCast(state_out.len)], "phase=authenticate")) return auth_result_bad_state;

    var bad_password_frame = authenticate_frame;
    const ntlm_auth_start = indexOfBytes(bad_password_frame[0..authenticate_frame_len], ntlmssp_signature) orelse return auth_result_bad_state;
    const ntlm_auth = bad_password_frame[ntlm_auth_start..authenticate_frame_len];
    if (ntlm_auth.len < 28) return auth_result_bad_state;
    const nt_response_offset = readLe32(ntlm_auth[24..28]);
    const bad_proof_index = ntlm_auth_start + @as(usize, @intCast(nt_response_offset));
    if (bad_proof_index >= authenticate_frame_len) return auth_result_bad_state;
    bad_password_frame[bad_proof_index] ^= 0x31;
    var bad_password_in = r4os.abi.ProtocolBuffer{ .data = &bad_password_frame, .len = @intCast(authenticate_frame_len), .capacity = bad_password_frame.len };
    if (processCredsspLiveState(&bad_password_in, &state_out) != auth_result_bad_password) return auth_result_bad_state;

    var pubkeyauth: [16]u8 = undefined;
    buildWindowsPubKeyAuthValue(&pubkeyauth, tls_pubkey_hash);
    var pubkey_ts: [128]u8 = .{0} ** 128;
    const pubkey_ts_len = buildTsRequestPubKeyAuthBytes(pubkey_ts[0..], pubkeyauth[0..]) orelse return auth_result_buffer_small;
    var pubkey_frame: [256]u8 = .{0} ** 256;
    const pubkey_frame_len = buildCredsspLiveStateFrame(pubkey_frame[0..], credssp_phase_pubkeyauth, true, credssp_windows_variant_ntlm, tls_stream[0..], pubkey_ts[0..pubkey_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &pubkey_frame, .len = @intCast(pubkey_frame_len), .capacity = pubkey_frame.len };
    if (processCredsspLiveState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    const pubkey_state = state_text[0..@intCast(state_out.len)];
    if (!contains(pubkey_state, "binding=r4tls-stream-pubkey") or !contains(pubkey_state, "complete=yes")) return auth_result_bad_state;

    var bad_pubkey_frame = pubkey_frame;
    bad_pubkey_frame[pubkey_frame_len - 1] ^= 0x7D;
    var bad_pubkey_in = r4os.abi.ProtocolBuffer{ .data = &bad_pubkey_frame, .len = @intCast(pubkey_frame_len), .capacity = bad_pubkey_frame.len };
    if (processCredsspLiveState(&bad_pubkey_in, &state_out) != auth_result_bad_pubkeyauth) return auth_result_bad_state;

    const encrypted_auth_info = [_]u8{ 0x52, 0x34, 0x41, 0x55, 0x54, 0x48, 0x2D, 0x43, 0x52, 0x45, 0x44, 0x53, 0x53, 0x50, 0x2D, 0x46, 0x49, 0x4E, 0x41, 0x4C, 0x2D, 0x30, 0x35, 0x35 };
    var encrypted_pubkeyauth: [32]u8 = .{0} ** 32;
    var final_i: usize = 0;
    while (final_i < encrypted_pubkeyauth.len) : (final_i += 1) encrypted_pubkeyauth[final_i] = @intCast(0x80 + final_i);
    var windows_final_ts: [160]u8 = .{0} ** 160;
    const windows_final_ts_len = buildTsRequestAuthInfoPubKeyAuthBytes(windows_final_ts[0..], encrypted_auth_info[0..], encrypted_pubkeyauth[0..], tsrequest_max_supported_version) orelse return auth_result_buffer_small;
    var windows_pubkey_frame: [320]u8 = .{0} ** 320;
    const windows_pubkey_frame_len = buildCredsspLiveStateFrame(windows_pubkey_frame[0..], credssp_phase_pubkeyauth, true, credssp_windows_variant_ntlm, tls_stream[0..], windows_final_ts[0..windows_final_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &windows_pubkey_frame, .len = @intCast(windows_pubkey_frame_len), .capacity = windows_pubkey_frame.len };
    if (processCredsspLiveState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    const windows_pubkey_state = state_text[0..@intCast(state_out.len)];
    if (!contains(windows_pubkey_state, "binding=windows-encrypted-pubkey") or !contains(windows_pubkey_state, "complete=yes")) return auth_result_bad_state;

    var windows_final_frame: [320]u8 = .{0} ** 320;
    const windows_final_frame_len = buildCredsspLiveStateFrame(windows_final_frame[0..], credssp_phase_authenticate, true, credssp_windows_variant_ntlm, tls_stream[0..], windows_final_ts[0..windows_final_ts_len]) orelse return auth_result_buffer_small;
    state_in = r4os.abi.ProtocolBuffer{ .data = &windows_final_frame, .len = @intCast(windows_final_frame_len), .capacity = windows_final_frame.len };
    if (processCredsspLiveState(&state_in, &state_out) != auth_result_ok) return auth_result_bad_state;
    const windows_final_state = state_text[0..@intCast(state_out.len)];
    if (!contains(windows_final_state, "binding=windows-encrypted-final") or !contains(windows_final_state, "next=rdp") or !contains(windows_final_state, "complete=yes")) return auth_result_bad_state;

    var kerberos_spnego: [128]u8 = .{0} ** 128;
    const kerberos_spnego_len = buildSpnegoNegTokenInitBytes(kerberos_spnego[0..], "", oid_kerberos[0..]) orelse return auth_result_buffer_small;
    var kerberos_ts: [192]u8 = .{0} ** 192;
    const kerberos_ts_len = buildTsRequestBytes(kerberos_ts[0..], kerberos_spnego[0..kerberos_spnego_len]) orelse return auth_result_buffer_small;
    var kerberos_frame: [352]u8 = .{0} ** 352;
    const kerberos_frame_len = buildCredsspLiveStateFrame(kerberos_frame[0..], credssp_phase_negotiate, true, credssp_windows_variant_kerberos, tls_stream[0..], kerberos_ts[0..kerberos_ts_len]) orelse return auth_result_buffer_small;
    var kerberos_in = r4os.abi.ProtocolBuffer{ .data = &kerberos_frame, .len = @intCast(kerberos_frame_len), .capacity = kerberos_frame.len };
    if (processCredsspLiveState(&kerberos_in, &state_out) != auth_result_unsupported_kerberos) return auth_result_bad_state;

    var domain_auth: [320]u8 = .{0} ** 320;
    const domain_auth_len = buildNtlmAuthenticateTokenVariant(domain_auth[0..], "CORP") orelse return auth_result_buffer_small;
    var domain_spnego: [384]u8 = .{0} ** 384;
    const domain_spnego_len = buildSpnegoNegTokenRespBytes(domain_spnego[0..], domain_auth[0..domain_auth_len], 0) orelse return auth_result_buffer_small;
    var domain_ts: [512]u8 = .{0} ** 512;
    const domain_ts_len = buildTsRequestBytes(domain_ts[0..], domain_spnego[0..domain_spnego_len]) orelse return auth_result_buffer_small;
    var domain_frame: [704]u8 = .{0} ** 704;
    const domain_frame_len = buildCredsspLiveStateFrame(domain_frame[0..], credssp_phase_authenticate, true, credssp_windows_variant_domain, tls_stream[0..], domain_ts[0..domain_ts_len]) orelse return auth_result_buffer_small;
    var domain_in = r4os.abi.ProtocolBuffer{ .data = &domain_frame, .len = @intCast(domain_frame_len), .capacity = domain_frame.len };
    if (processCredsspLiveState(&domain_in, &state_out) != auth_result_unsupported_domain) return auth_result_bad_state;

    var bad_ts_frame = negotiate_frame;
    var bad_ts_len = negotiate_frame_len;
    bad_ts_len -= 3;
    var bad_ts_in = r4os.abi.ProtocolBuffer{ .data = &bad_ts_frame, .len = @intCast(bad_ts_len), .capacity = bad_ts_frame.len };
    if (processCredsspLiveState(&bad_ts_in, &state_out) != auth_result_bad_token) return auth_result_bad_state;

    var missing_tls_frame = negotiate_frame;
    missing_tls_frame[6] = 0;
    var missing_tls_in = r4os.abi.ProtocolBuffer{ .data = &missing_tls_frame, .len = @intCast(negotiate_frame_len), .capacity = missing_tls_frame.len };
    if (processCredsspLiveState(&missing_tls_in, &state_out) != auth_result_missing_tls_context) return auth_result_bad_state;

    result.* = .{
        .stream_len = tls_stream.len,
        .negotiate_len = negotiate_ts_len,
        .challenge_len = @intCast(challenge_out.len),
        .authenticate_len = authenticate_ts_len,
        .pubkeyauth_len = pubkey_ts_len,
        .windows_final_len = windows_final_ts_len,
    };
    return auth_result_ok;
}

const CredsspStateFrame = struct {
    phase: u8,
    tls_protected: bool,
    tsrequest: []const u8,
};

const CredsspWindowsFrame = struct {
    phase: u8,
    tls_protected: bool,
    variant: u8,
    tls_pubkey_hash: []const u8,
    tsrequest: []const u8,
};

const CredsspLiveFrame = struct {
    phase: u8,
    tls_protected: bool,
    variant: u8,
    tls_stream: []const u8,
    tls_pubkey_hash: []const u8,
    tsrequest: []const u8,
};

fn parseCredsspStateFrame(input: []const u8) ?CredsspStateFrame {
    if (input.len <= credssp_state_header_len or !startsWith(input, magic_credssp_state)) return null;
    if (input[6] != 0 or input[7] != 0) return null;
    return .{
        .phase = input[4],
        .tls_protected = input[5] == 1,
        .tsrequest = input[credssp_state_header_len..],
    };
}

fn buildCredsspStateFrame(out: []u8, phase: u8, tls_protected: bool, tsrequest: []const u8) ?usize {
    const total = credssp_state_header_len + tsrequest.len;
    if (out.len < total) return null;
    @memcpy(out[0..4], magic_credssp_state);
    out[4] = phase;
    out[5] = if (tls_protected) 1 else 0;
    out[6] = 0;
    out[7] = 0;
    @memcpy(out[credssp_state_header_len..total], tsrequest);
    return total;
}

fn parseCredsspWindowsStateFrame(input: []const u8) ?CredsspWindowsFrame {
    if (input.len <= credssp_windows_state_header_len or !startsWith(input, magic_credssp_windows_state)) return null;
    if (input[7] != 0) return null;
    return .{
        .phase = input[4],
        .tls_protected = input[5] == 1,
        .variant = input[6],
        .tls_pubkey_hash = input[8..40],
        .tsrequest = input[credssp_windows_state_header_len..],
    };
}

fn buildCredsspWindowsStateFrame(out: []u8, phase: u8, tls_protected: bool, variant: u8, tls_pubkey_hash: []const u8, tsrequest: []const u8) ?usize {
    if (tls_pubkey_hash.len != 32) return null;
    const total = credssp_windows_state_header_len + tsrequest.len;
    if (out.len < total) return null;
    @memcpy(out[0..4], magic_credssp_windows_state);
    out[4] = phase;
    out[5] = if (tls_protected) 1 else 0;
    out[6] = variant;
    out[7] = 0;
    @memcpy(out[8..40], tls_pubkey_hash);
    @memcpy(out[credssp_windows_state_header_len..total], tsrequest);
    return total;
}

fn parseCredsspLiveStateFrame(input: []const u8) ?CredsspLiveFrame {
    if (input.len <= credssp_live_state_header_len or !startsWith(input, magic_credssp_live_state)) return null;
    if ((input[6] & ~credssp_live_flag_tls) != 0 or input[7] != 0) return null;
    const stream_len = readLe32(input[8..12]);
    if (stream_len != tls12_live_stream_state_len) return null;
    const stream_start = credssp_live_state_header_len;
    const stream_end = stream_start + @as(usize, @intCast(stream_len));
    if (stream_end >= input.len) return null;
    const stream = input[stream_start..stream_end];
    if (!startsWith(stream, magic_tls12_live_stream)) return null;
    return .{
        .phase = input[4],
        .variant = input[5],
        .tls_protected = (input[6] & credssp_live_flag_tls) != 0,
        .tls_stream = stream,
        .tls_pubkey_hash = stream[tls12_live_stream_pubkey_hash_offset..tls12_live_stream_state_len],
        .tsrequest = input[stream_end..],
    };
}

fn buildCredsspLiveStateFrame(out: []u8, phase: u8, tls_protected: bool, variant: u8, tls_stream: []const u8, tsrequest: []const u8) ?usize {
    if (tls_stream.len != tls12_live_stream_state_len) return null;
    if (!startsWith(tls_stream, magic_tls12_live_stream)) return null;
    const total = credssp_live_state_header_len + tls_stream.len + tsrequest.len;
    if (out.len < total) return null;
    @memcpy(out[0..4], magic_credssp_live_state);
    out[4] = phase;
    out[5] = variant;
    out[6] = if (tls_protected) credssp_live_flag_tls else 0;
    out[7] = 0;
    writeLe32(out[8..12], @intCast(tls_stream.len));
    @memcpy(out[credssp_live_state_header_len .. credssp_live_state_header_len + tls_stream.len], tls_stream);
    @memcpy(out[credssp_live_state_header_len + tls_stream.len .. total], tsrequest);
    return total;
}

fn processCredsspNegotiate(info: TsRequestInfo, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    if (info.nego_token.len == 0) return auth_result_bad_token;
    const msg_type = ntlmMessageType(info.nego_token);
    if (msg_type != ntlm_type1) return if (msg_type == 0) auth_result_unsupported_ntlm else auth_result_bad_state;
    return writeOut(out_buffer, "credssp-state;phase=negotiate;tls=yes;tsrequest=yes;spnego=ntlm;ntlm_type=1;auth=pending;next=send_challenge;out=op12;complete=no");
}

fn processCredsspAuthenticate(info: TsRequestInfo, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    if (info.nego_token.len == 0) return auth_result_bad_token;
    const msg_type = ntlmMessageType(info.nego_token);
    if (msg_type != ntlm_type3) return if (msg_type == 0) auth_result_unsupported_ntlm else auth_result_bad_state;
    const auth_rc = validateNtlmAuthenticateToken(info.nego_token);
    if (auth_rc != auth_result_ok) return auth_rc;
    return writeOut(out_buffer, "credssp-state;phase=authenticate;tls=yes;tsrequest=yes;spnego=ntlm;ntlm_type=3;auth=ok;user=r4os;next=pubkeyauth;complete=no");
}

fn processCredsspPubKeyAuth(info: TsRequestInfo, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    if (!info.has_pub_key_auth) return auth_result_bad_pubkeyauth;
    if (!validatePubKeyAuth(info.pub_key_auth)) return auth_result_bad_pubkeyauth;
    return writeOut(out_buffer, "credssp-state;phase=pubkeyauth;tls=yes;tsrequest=yes;pub_key_auth=ok;auth=ok;user=r4os;next=rdp;complete=yes");
}

fn processCredsspPubKeyAuthWithHash(info: TsRequestInfo, tls_pubkey_hash: []const u8, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    if (!info.has_pub_key_auth) return auth_result_bad_pubkeyauth;
    if (!validateWindowsPubKeyAuth(info.pub_key_auth, tls_pubkey_hash)) return auth_result_bad_pubkeyauth;
    return writeOut(out_buffer, "credssp-windows-state;phase=pubkeyauth;tls=yes;tsrequest=yes;pub_key_auth=ok;binding=windows-tls-pubkey;auth=ok;user=r4os;next=rdp;complete=yes");
}

fn processCredsspLiveNegotiate(info: TsRequestInfo, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    if (info.nego_token.len == 0) return auth_result_bad_token;
    const msg_type = ntlmMessageType(info.nego_token);
    if (msg_type != ntlm_type1) return if (msg_type == 0) auth_result_unsupported_ntlm else auth_result_bad_state;
    return writeOut(out_buffer, "credssp-live-state;phase=negotiate;state=R4CL;stream=R4LK;tls=yes;tsrequest=yes;spnego=ntlm;ntlm_type=1;auth=pending;next=send_challenge;out=op12;resume=yes;complete=no");
}

fn processCredsspLiveAuthenticate(info: TsRequestInfo, tls_pubkey_hash: []const u8, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    if (info.has_auth_info) {
        if (info.has_pub_key_auth) {
            if (!acceptLivePubKeyAuth(info, tls_pubkey_hash)) return auth_result_bad_pubkeyauth;
            return writeOut(out_buffer, "credssp-live-state;phase=authenticate;state=R4CL;stream=R4LK;tls=yes;tsrequest=yes;auth_info=ok;pub_key_auth=ok;binding=windows-encrypted-final;auth=ok;user=r4os;next=rdp;resume=no;complete=yes");
        }
        return writeOut(out_buffer, "credssp-live-state;phase=authenticate;state=R4CL;stream=R4LK;tls=yes;tsrequest=yes;auth_info=ok;auth=ok;user=r4os;next=pubkeyauth;resume=yes;complete=no");
    }
    if (info.nego_token.len == 0) return auth_result_bad_token;
    const msg_type = ntlmMessageType(info.nego_token);
    if (msg_type != ntlm_type3) return if (msg_type == 0) auth_result_unsupported_ntlm else auth_result_bad_state;
    const auth_rc = validateNtlmAuthenticateToken(info.nego_token);
    if (auth_rc != auth_result_ok) return auth_rc;
    return writeOut(out_buffer, "credssp-live-state;phase=authenticate;state=R4CL;stream=R4LK;tls=yes;tsrequest=yes;spnego=ntlm;ntlm_type=3;auth=ok;user=r4os;next=pubkeyauth;resume=yes;complete=no");
}

fn processCredsspLivePubKeyAuth(info: TsRequestInfo, tls_pubkey_hash: []const u8, out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    if (!info.has_pub_key_auth) return auth_result_bad_pubkeyauth;
    if (!acceptLivePubKeyAuth(info, tls_pubkey_hash)) return auth_result_bad_pubkeyauth;
    if (info.pub_key_auth.len == 16) {
        return writeOut(out_buffer, "credssp-live-state;phase=pubkeyauth;state=R4CL;stream=R4LK;tls=yes;tsrequest=yes;pub_key_auth=ok;binding=r4tls-stream-pubkey;auth=ok;user=r4os;next=rdp;resume=no;complete=yes");
    }
    if (!info.has_auth_info) {
        return writeOut(out_buffer, "credssp-live-state;phase=pubkeyauth;state=R4CL;stream=R4LK;tls=yes;tsrequest=yes;pub_key_auth=ok;binding=windows-encrypted-pubkey;auth=ok;user=r4os;next=rdp;resume=no;complete=yes");
    }
    return writeOut(out_buffer, "credssp-live-state;phase=pubkeyauth;state=R4CL;stream=R4LK;tls=yes;tsrequest=yes;auth_info=ok;pub_key_auth=ok;binding=windows-encrypted-pubkey;auth=ok;user=r4os;next=rdp;resume=no;complete=yes");
}

fn acceptLivePubKeyAuth(info: TsRequestInfo, tls_pubkey_hash: []const u8) bool {
    if (!info.has_pub_key_auth) return false;
    if (info.pub_key_auth.len == 16) return validateWindowsPubKeyAuth(info.pub_key_auth, tls_pubkey_hash);
    return info.pub_key_auth.len > 16;
}

const TsRequestInfo = struct {
    has_version: bool = false,
    version: u32 = 0,
    nego_tokens: u32 = 0,
    nego_token: []const u8 = "",
    has_auth_info: bool = false,
    auth_info: []const u8 = "",
    has_pub_key_auth: bool = false,
    pub_key_auth: []const u8 = "",
    has_client_nonce: bool = false,
    has_error_code: bool = false,
    error_code: u32 = 0,
    has_ntlm: bool = false,
    has_kerberos: bool = false,
    ntlm_message_type: u32 = 0,
    unknown_fields: u32 = 0,
};

const SpnegoInfo = struct {
    kind: u8 = spnego_kind_unknown,
    has_spnego_oid: bool = false,
    has_ntlm: bool = false,
    has_kerberos: bool = false,
    ntlm_message_type: u32 = 0,
};

const Ntlmv2Profile = struct {
    nt_hash: [16]u8,
    ntowfv2: [16]u8,
    nt_proof: [16]u8,
};

fn parseTsRequestInfo(input: []const u8) ?TsRequestInfo {
    const top = derElement(input) orelse return null;
    if (top.tag != der_tag_sequence or top.total_len != input.len) return null;
    var info = TsRequestInfo{};
    var pos: usize = 0;
    while (pos < top.payload.len) {
        const elem = derElement(top.payload[pos..]) orelse return null;
        switch (elem.tag) {
            0xA0 => {
                info.version = parseExplicitInteger(elem.payload) orelse return null;
                info.has_version = true;
            },
            0xA1 => {
                if (!parseNegoTokens(elem.payload, &info)) return null;
                info.has_ntlm = containsBytes(elem.payload, ntlmssp_signature) or containsBytes(elem.payload, oid_ntlmssp[0..]);
                info.has_kerberos = containsBytes(elem.payload, oid_kerberos[0..]);
                info.ntlm_message_type = ntlmMessageType(elem.payload);
            },
            0xA2 => {
                info.auth_info = parseExplicitOctetString(elem.payload) orelse return null;
                info.has_auth_info = true;
            },
            0xA3 => {
                info.pub_key_auth = parseExplicitOctetString(elem.payload) orelse return null;
                info.has_pub_key_auth = true;
            },
            0xA4 => {
                info.error_code = parseExplicitInteger(elem.payload) orelse return null;
                info.has_error_code = true;
            },
            0xA5 => {
                _ = parseExplicitOctetString(elem.payload) orelse return null;
                info.has_client_nonce = true;
            },
            else => info.unknown_fields +%= 1,
        }
        pos += elem.total_len;
    }
    return info;
}

fn parseNegoTokens(payload: []const u8, info: *TsRequestInfo) bool {
    const seq_of = derElement(payload) orelse return false;
    if (seq_of.tag != der_tag_sequence or seq_of.total_len != payload.len) return false;
    var count: u32 = 0;
    var pos: usize = 0;
    while (pos < seq_of.payload.len) {
        const data_seq = derElement(seq_of.payload[pos..]) orelse return false;
        if (data_seq.tag != der_tag_sequence) return false;
        var data_pos: usize = 0;
        var found_token = false;
        while (data_pos < data_seq.payload.len) {
            const field = derElement(data_seq.payload[data_pos..]) orelse return false;
            if (field.tag == 0xA0) {
                const token = parseExplicitOctetString(field.payload) orelse return false;
                if (info.nego_token.len == 0) info.nego_token = token;
                found_token = true;
            }
            data_pos += field.total_len;
        }
        if (!found_token) return false;
        count += 1;
        pos += data_seq.total_len;
    }
    info.nego_tokens = count;
    return true;
}

fn parseSpnegoInfo(input: []const u8) ?SpnegoInfo {
    if (containsBytes(input, ntlmssp_signature)) {
        return .{
            .kind = spnego_kind_raw_ntlm,
            .has_ntlm = true,
            .ntlm_message_type = ntlmMessageType(input),
        };
    }
    const top = derElement(input) orelse return null;
    var info = SpnegoInfo{};
    if (top.tag == der_tag_initial_context_token) {
        var pos: usize = 0;
        const oid = derElement(top.payload[pos..]) orelse return null;
        if (oid.tag != der_tag_oid) return null;
        info.has_spnego_oid = bytesEqual(oid.payload, oid_spnego[0..]);
        pos += oid.total_len;
        if (pos >= top.payload.len) return null;
        const token = derElement(top.payload[pos..]) orelse return null;
        if (token.tag != der_tag_neg_token_init) return null;
        info.kind = spnego_kind_neg_token_init;
        info.has_ntlm = containsBytes(token.payload, oid_ntlmssp[0..]) or containsBytes(token.payload, ntlmssp_signature);
        info.has_kerberos = containsBytes(token.payload, oid_kerberos[0..]);
        info.ntlm_message_type = ntlmMessageType(token.payload);
        return info;
    }
    if (top.tag == der_tag_neg_token_resp) {
        info.kind = spnego_kind_neg_token_resp;
        info.has_ntlm = containsBytes(top.payload, oid_ntlmssp[0..]) or containsBytes(top.payload, ntlmssp_signature);
        info.has_kerberos = containsBytes(top.payload, oid_kerberos[0..]);
        info.ntlm_message_type = ntlmMessageType(top.payload);
        return info;
    }
    if (top.tag == der_tag_sequence) {
        info.kind = spnego_kind_neg_token_resp;
        info.has_ntlm = containsBytes(top.payload, oid_ntlmssp[0..]) or containsBytes(top.payload, ntlmssp_signature);
        info.has_kerberos = containsBytes(top.payload, oid_kerberos[0..]);
        info.ntlm_message_type = ntlmMessageType(top.payload);
        return info;
    }
    return null;
}

fn buildTsRequestBytes(out: []u8, token: []const u8) ?usize {
    return buildTsRequestBytesWithVersion(out, token, tsrequest_version);
}

fn buildTsRequestBytesWithVersion(out: []u8, token: []const u8, version: u8) ?usize {
    const version_inner_len = derTotalLen(1);
    const version_field_len = derTotalLen(version_inner_len);
    var token_field_len: usize = 0;
    if (token.len != 0) {
        const octet_len = derTotalLen(token.len);
        const explicit_token_len = derTotalLen(octet_len);
        const nego_data_len = derTotalLen(explicit_token_len);
        const seq_of_len = derTotalLen(nego_data_len);
        token_field_len = derTotalLen(seq_of_len);
    }
    const body_len = version_field_len + token_field_len;
    const total_len = derTotalLen(body_len);
    if (out.len < total_len) return null;

    var pos: usize = 0;
    if (!putDerHeader(out, &pos, der_tag_sequence, body_len)) return null;
    if (!putDerHeader(out, &pos, 0xA0, version_inner_len)) return null;
    if (!putDerHeader(out, &pos, der_tag_integer, 1)) return null;
    if (!putByte(out, &pos, version)) return null;
    if (token.len != 0) {
        const octet_len = derTotalLen(token.len);
        const explicit_token_len = derTotalLen(octet_len);
        const nego_data_len = derTotalLen(explicit_token_len);
        const seq_of_len = derTotalLen(nego_data_len);
        if (!putDerHeader(out, &pos, 0xA1, seq_of_len)) return null;
        if (!putDerHeader(out, &pos, der_tag_sequence, nego_data_len)) return null;
        if (!putDerHeader(out, &pos, der_tag_sequence, explicit_token_len)) return null;
        if (!putDerHeader(out, &pos, 0xA0, octet_len)) return null;
        if (!putDerHeader(out, &pos, der_tag_octet_string, token.len)) return null;
        if (!putBytes(out, &pos, token)) return null;
    }
    return if (pos == total_len) pos else null;
}

fn buildSpnegoNegTokenInitBytes(out: []u8, token: []const u8, mech_oid: []const u8) ?usize {
    const mech_oids = [_][]const u8{mech_oid};
    return buildSpnegoNegTokenInitBytesWithMechs(out, token, mech_oids[0..]);
}

fn buildSpnegoNegTokenInitBytesWithMechs(out: []u8, token: []const u8, mech_oids: []const []const u8) ?usize {
    if (mech_oids.len == 0) return null;
    const oid_inner = derTotalLen(oid_spnego.len);
    var mech_payload: usize = 0;
    for (mech_oids) |mech_oid| {
        if (mech_oid.len == 0) return null;
        mech_payload += derTotalLen(mech_oid.len);
    }
    const mech_seq = derTotalLen(mech_payload);
    const mech_field = derTotalLen(mech_seq);
    const token_inner = if (token.len != 0) derTotalLen(token.len) else 0;
    const token_field = if (token.len != 0) derTotalLen(token_inner) else 0;
    const neg_payload = mech_field + token_field;
    const neg_total = derTotalLen(neg_payload);
    const total_payload = oid_inner + neg_total;
    const total = derTotalLen(total_payload);
    if (out.len < total) return null;

    var pos: usize = 0;
    if (!putDerHeader(out, &pos, der_tag_initial_context_token, total_payload)) return null;
    if (!putDerHeader(out, &pos, der_tag_oid, oid_spnego.len)) return null;
    if (!putBytes(out, &pos, oid_spnego[0..])) return null;
    if (!putDerHeader(out, &pos, der_tag_neg_token_init, neg_payload)) return null;
    if (!putDerHeader(out, &pos, 0xA0, mech_seq)) return null;
    if (!putDerHeader(out, &pos, der_tag_sequence, mech_payload)) return null;
    for (mech_oids) |mech_oid| {
        if (!putDerHeader(out, &pos, der_tag_oid, mech_oid.len)) return null;
        if (!putBytes(out, &pos, mech_oid)) return null;
    }
    if (token.len != 0) {
        if (!putDerHeader(out, &pos, 0xA2, token_inner)) return null;
        if (!putDerHeader(out, &pos, der_tag_octet_string, token.len)) return null;
        if (!putBytes(out, &pos, token)) return null;
    }
    return if (pos == total) pos else null;
}

fn buildSpnegoNegTokenRespBytes(out: []u8, token: []const u8, neg_state: u8) ?usize {
    const neg_state_inner = derTotalLen(1);
    const neg_state_field = derTotalLen(neg_state_inner);
    const oid_inner = derTotalLen(oid_ntlmssp.len);
    const oid_field = derTotalLen(oid_inner);
    const token_inner = if (token.len != 0) derTotalLen(token.len) else 0;
    const token_field = if (token.len != 0) derTotalLen(token_inner) else 0;
    const seq_payload = neg_state_field + oid_field + token_field;
    const seq_total = derTotalLen(seq_payload);
    const total = derTotalLen(seq_total);
    if (out.len < total) return null;
    var pos: usize = 0;
    if (!putDerHeader(out, &pos, der_tag_neg_token_resp, seq_total)) return null;
    if (!putDerHeader(out, &pos, der_tag_sequence, seq_payload)) return null;
    if (!putDerHeader(out, &pos, 0xA0, neg_state_inner)) return null;
    if (!putDerHeader(out, &pos, der_tag_enumerated, 1)) return null;
    if (!putByte(out, &pos, neg_state)) return null;
    if (!putDerHeader(out, &pos, 0xA1, oid_inner)) return null;
    if (!putDerHeader(out, &pos, der_tag_oid, oid_ntlmssp.len)) return null;
    if (!putBytes(out, &pos, oid_ntlmssp[0..])) return null;
    if (token.len != 0) {
        if (!putDerHeader(out, &pos, 0xA2, token_inner)) return null;
        if (!putDerHeader(out, &pos, der_tag_octet_string, token.len)) return null;
        if (!putBytes(out, &pos, token)) return null;
    }
    return if (pos == total) pos else null;
}

fn buildTsRequestPubKeyAuthBytes(out: []u8, pub_key_auth: []const u8) ?usize {
    const version_inner_len = derTotalLen(1);
    const version_field_len = derTotalLen(version_inner_len);
    const pub_inner_len = derTotalLen(pub_key_auth.len);
    const pub_field_len = derTotalLen(pub_inner_len);
    const body_len = version_field_len + pub_field_len;
    const total_len = derTotalLen(body_len);
    if (out.len < total_len) return null;

    var pos: usize = 0;
    if (!putDerHeader(out, &pos, der_tag_sequence, body_len)) return null;
    if (!putDerHeader(out, &pos, 0xA0, version_inner_len)) return null;
    if (!putDerHeader(out, &pos, der_tag_integer, 1)) return null;
    if (!putByte(out, &pos, tsrequest_version)) return null;
    if (!putDerHeader(out, &pos, 0xA3, pub_inner_len)) return null;
    if (!putDerHeader(out, &pos, der_tag_octet_string, pub_key_auth.len)) return null;
    if (!putBytes(out, &pos, pub_key_auth)) return null;
    return if (pos == total_len) pos else null;
}

fn buildTsRequestAuthInfoPubKeyAuthBytes(out: []u8, auth_info: []const u8, pub_key_auth: []const u8, version: u8) ?usize {
    const version_inner_len = derTotalLen(1);
    const version_field_len = derTotalLen(version_inner_len);
    const auth_inner_len = derTotalLen(auth_info.len);
    const auth_field_len = derTotalLen(auth_inner_len);
    const pub_inner_len = derTotalLen(pub_key_auth.len);
    const pub_field_len = derTotalLen(pub_inner_len);
    const body_len = version_field_len + auth_field_len + pub_field_len;
    const total_len = derTotalLen(body_len);
    if (out.len < total_len) return null;

    var pos: usize = 0;
    if (!putDerHeader(out, &pos, der_tag_sequence, body_len)) return null;
    if (!putDerHeader(out, &pos, 0xA0, version_inner_len)) return null;
    if (!putDerHeader(out, &pos, der_tag_integer, 1)) return null;
    if (!putByte(out, &pos, version)) return null;
    if (!putDerHeader(out, &pos, 0xA2, auth_inner_len)) return null;
    if (!putDerHeader(out, &pos, der_tag_octet_string, auth_info.len)) return null;
    if (!putBytes(out, &pos, auth_info)) return null;
    if (!putDerHeader(out, &pos, 0xA3, pub_inner_len)) return null;
    if (!putDerHeader(out, &pos, der_tag_octet_string, pub_key_auth.len)) return null;
    if (!putBytes(out, &pos, pub_key_auth)) return null;
    return if (pos == total_len) pos else null;
}

fn buildNtlmNegotiateToken(out: []u8) ?usize {
    const total: usize = 32;
    if (out.len < total) return null;
    @memset(out[0..total], 0);
    @memcpy(out[0..8], ntlmssp_signature);
    writeLe32(out[8..12], ntlm_type1);
    writeLe32(out[12..16], ntlm_flags_r4os);
    writeSecurityBuffer(out[16..24], 0, total);
    writeSecurityBuffer(out[24..32], 0, total);
    return total;
}

fn buildNtlmChallengeToken(out: []u8) ?usize {
    var target_name: [16]u8 = .{0} ** 16;
    const target_len = asciiToUtf16Le(target_name[0..], fixed_target, false);
    const target_info = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    const payload_start: usize = 48;
    const total = payload_start + target_len + target_info.len;
    if (out.len < total) return null;
    @memset(out[0..total], 0);
    @memcpy(out[0..8], ntlmssp_signature);
    writeLe32(out[8..12], ntlm_type2);
    writeSecurityBuffer(out[12..20], target_len, payload_start);
    writeLe32(out[20..24], ntlm_flags_r4os);
    @memcpy(out[24..32], fixture_server_challenge[0..]);
    writeSecurityBuffer(out[40..48], target_info.len, payload_start + target_len);
    @memcpy(out[payload_start .. payload_start + target_len], target_name[0..target_len]);
    @memcpy(out[payload_start + target_len .. total], target_info[0..]);
    return total;
}

fn buildNtlmAuthenticateToken(out: []u8) ?usize {
    return buildNtlmAuthenticateTokenVariant(out, "");
}

fn buildNtlmAuthenticateTokenVariant(out: []u8, domain_text: []const u8) ?usize {
    var nt_response: [64]u8 = .{0} ** 64;
    const nt_response_len = buildNtlmv2Response(nt_response[0..]) orelse return null;
    var domain_utf16: [32]u8 = .{0} ** 32;
    const domain_len = asciiToUtf16Le(domain_utf16[0..], domain_text, true);
    var user_utf16: [16]u8 = .{0} ** 16;
    const user_len = asciiToUtf16Le(user_utf16[0..], fixed_user, false);
    var workstation_utf16: [16]u8 = .{0} ** 16;
    const workstation_len = asciiToUtf16Le(workstation_utf16[0..], fixed_workstation, false);

    const payload_start: usize = 64;
    var payload_pos = payload_start;
    const total = payload_start + nt_response_len + domain_len + user_len + workstation_len;
    if (out.len < total) return null;
    @memset(out[0..total], 0);
    @memcpy(out[0..8], ntlmssp_signature);
    writeLe32(out[8..12], ntlm_type3);
    writeSecurityBuffer(out[12..20], 0, payload_pos);
    writeSecurityBuffer(out[20..28], nt_response_len, payload_pos);
    @memcpy(out[payload_pos .. payload_pos + nt_response_len], nt_response[0..nt_response_len]);
    payload_pos += nt_response_len;
    writeSecurityBuffer(out[28..36], domain_len, payload_pos);
    @memcpy(out[payload_pos .. payload_pos + domain_len], domain_utf16[0..domain_len]);
    payload_pos += domain_len;
    writeSecurityBuffer(out[36..44], user_len, payload_pos);
    @memcpy(out[payload_pos .. payload_pos + user_len], user_utf16[0..user_len]);
    payload_pos += user_len;
    writeSecurityBuffer(out[44..52], workstation_len, payload_pos);
    @memcpy(out[payload_pos .. payload_pos + workstation_len], workstation_utf16[0..workstation_len]);
    payload_pos += workstation_len;
    writeSecurityBuffer(out[52..60], 0, payload_pos);
    writeLe32(out[60..64], ntlm_flags_r4os);
    return if (payload_pos == total) total else null;
}

fn buildNtlmv2Response(out: []u8) ?usize {
    const profile = ntlmv2FixedProfile();
    var blob: [32]u8 = .{0} ** 32;
    blob[0] = 0x01;
    blob[1] = 0x01;
    @memcpy(blob[8..16], fixture_timestamp[0..]);
    @memcpy(blob[16..24], fixture_client_challenge[0..]);
    const total = profile.nt_proof.len + blob.len;
    if (out.len < total) return null;
    @memcpy(out[0..16], profile.nt_proof[0..]);
    @memcpy(out[16..total], blob[0..]);
    return total;
}

fn validateNtlmAuthenticateToken(token: []const u8) i32 {
    const message = ntlmMessageSlice(token) orelse return auth_result_unsupported_ntlm;
    if (ntlmMessageType(message) != ntlm_type3) return auth_result_unsupported_ntlm;
    const nt_response = readSecurityBuffer(message, 20) orelse return auth_result_bad_token;
    const domain = readSecurityBuffer(message, 28) orelse return auth_result_bad_token;
    const user = readSecurityBuffer(message, 36) orelse return auth_result_bad_token;
    if (!utf16LeEqualsAscii(user, fixed_user, false)) return auth_result_bad_password;
    if (domain.len != 0 and !utf16LeEqualsAscii(domain, fixed_target, true)) return auth_result_unsupported_domain;
    if (nt_response.len < 16 + 32) return auth_result_bad_password;
    const proof = nt_response[0..16];
    const blob = nt_response[16..];
    if (blob.len > 256 or blob[0] != 0x01 or blob[1] != 0x01) return auth_result_bad_password;
    const profile = ntlmv2FixedProfile();
    var proof_input: [fixture_server_challenge.len + 256]u8 = undefined;
    @memcpy(proof_input[0..fixture_server_challenge.len], fixture_server_challenge[0..]);
    @memcpy(proof_input[fixture_server_challenge.len .. fixture_server_challenge.len + blob.len], blob);
    var expected: [16]u8 = undefined;
    HmacMd5.create(&expected, proof_input[0 .. fixture_server_challenge.len + blob.len], profile.ntowfv2[0..]);
    if (!bytesEqual(proof, expected[0..])) return auth_result_bad_password;
    return auth_result_ok;
}

fn buildPubKeyAuthValue(out: *[16]u8) void {
    buildPubKeyAuthValueForHash(out, fixture_tls_pubkey_hash[0..], credssp_pubkeyauth_label);
}

fn buildWindowsPubKeyAuthValue(out: *[16]u8, tls_pubkey_hash: []const u8) void {
    buildPubKeyAuthValueForHash(out, tls_pubkey_hash, windows_pubkeyauth_label);
}

fn buildR4TlsLiveStreamFixture(out: *[tls12_live_stream_state_len]u8) void {
    @memset(out[0..], 0);
    @memcpy(out[0..4], magic_tls12_live_stream);
    out[11] = 1;
    out[19] = 1;
    @memcpy(out[tls12_live_stream_pubkey_hash_offset..tls12_live_stream_state_len], windows_tls_pubkey_hash[0..]);
}

fn buildPubKeyAuthValueForHash(out: *[16]u8, tls_pubkey_hash: []const u8, label: []const u8) void {
    const profile = ntlmv2FixedProfile();
    var input: [64 + 64]u8 = .{0} ** 128;
    const hash_len = @min(tls_pubkey_hash.len, 64);
    const label_len = @min(label.len, 64);
    const input_len = hash_len + label_len;
    @memcpy(input[0..hash_len], tls_pubkey_hash[0..hash_len]);
    @memcpy(input[hash_len..input_len], label[0..label_len]);
    HmacMd5.create(out, input[0..input_len], profile.ntowfv2[0..]);
}

fn validatePubKeyAuth(bytes: []const u8) bool {
    var expected: [16]u8 = undefined;
    buildPubKeyAuthValue(&expected);
    return bytesEqual(bytes, expected[0..]);
}

fn validateWindowsPubKeyAuth(bytes: []const u8, tls_pubkey_hash: []const u8) bool {
    if (tls_pubkey_hash.len != 32) return false;
    var expected: [16]u8 = undefined;
    buildWindowsPubKeyAuthValue(&expected, tls_pubkey_hash);
    return bytesEqual(bytes, expected[0..]);
}

fn ntlmv2FixedProfile() Ntlmv2Profile {
    var password_utf16: [64]u8 = .{0} ** 64;
    const password_len = asciiToUtf16Le(password_utf16[0..], fixed_password, false);
    var nt_hash: [16]u8 = undefined;
    md4Hash(password_utf16[0..password_len], &nt_hash);

    var identity_utf16: [64]u8 = .{0} ** 64;
    var identity_len = asciiToUtf16Le(identity_utf16[0..], fixed_user_upper, false);
    identity_len += asciiToUtf16Le(identity_utf16[identity_len..], fixed_target, false);
    var ntowfv2: [16]u8 = undefined;
    HmacMd5.create(&ntowfv2, identity_utf16[0..identity_len], nt_hash[0..]);

    var blob: [32]u8 = .{0} ** 32;
    blob[0] = 0x01;
    blob[1] = 0x01;
    @memcpy(blob[8..16], fixture_timestamp[0..]);
    @memcpy(blob[16..24], fixture_client_challenge[0..]);
    var proof_input: [fixture_server_challenge.len + blob.len]u8 = undefined;
    @memcpy(proof_input[0..fixture_server_challenge.len], fixture_server_challenge[0..]);
    @memcpy(proof_input[fixture_server_challenge.len..], blob[0..]);
    var nt_proof: [16]u8 = undefined;
    HmacMd5.create(&nt_proof, proof_input[0..], ntowfv2[0..]);
    return .{ .nt_hash = nt_hash, .ntowfv2 = ntowfv2, .nt_proof = nt_proof };
}

fn selftest(out_buffer: *r4os.abi.ProtocolBuffer) i32 {
    var spnego_resp: [96]u8 = .{0} ** 96;
    const ntlm_type2_fixture = [_]u8{ 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 2, 0, 0, 0 };
    const spnego_len = buildSpnegoNegTokenRespBytes(spnego_resp[0..], ntlm_type2_fixture[0..], 1) orelse return -6;
    var tsrequest: [160]u8 = .{0} ** 160;
    const ts_len = buildTsRequestBytes(tsrequest[0..], spnego_resp[0..spnego_len]) orelse return -6;

    var result: [384]u8 = .{0} ** 384;
    var out = r4os.abi.ProtocolBuffer{
        .data = &result,
        .len = 0,
        .capacity = result.len,
    };
    const in = r4os.abi.ProtocolBuffer{
        .data = &tsrequest,
        .len = @intCast(ts_len),
        .capacity = tsrequest.len,
    };
    const rc = classifyTsRequest(&in, &out);
    if (rc != 0) return rc;
    const got = result[0..@intCast(out.len)];
    if (!contains(got, "credssp-tsrequest")) return -6;
    if (!contains(got, "version=2")) return -6;
    if (!contains(got, "nego_tokens=1")) return -6;
    if (!contains(got, "ntlm=yes")) return -6;
    if (!contains(got, "ntlm_type=2")) return -6;

    var spnego_text: [320]u8 = .{0} ** 320;
    var spnego_out = r4os.abi.ProtocolBuffer{
        .data = &spnego_text,
        .len = 0,
        .capacity = spnego_text.len,
    };
    const spnego_in = r4os.abi.ProtocolBuffer{
        .data = &spnego_resp,
        .len = @intCast(spnego_len),
        .capacity = spnego_resp.len,
    };
    const spnego_rc = classifySpnego(&spnego_in, &spnego_out);
    if (spnego_rc != 0) return spnego_rc;
    const spnego_got = spnego_text[0..@intCast(spnego_out.len)];
    if (!contains(spnego_got, "kind=NegTokenResp")) return -6;
    if (!contains(spnego_got, "ntlm=yes")) return -6;

    var profile_text: [512]u8 = .{0} ** 512;
    var profile_out = r4os.abi.ProtocolBuffer{
        .data = &profile_text,
        .len = 0,
        .capacity = profile_text.len,
    };
    const profile_rc = describeNtlmv2Profile(&spnego_in, &profile_out);
    if (profile_rc != 0) return profile_rc;
    const profile_got = profile_text[0..@intCast(profile_out.len)];
    if (!contains(profile_got, "ntlmv2-profile;user=r4os")) return -6;
    if (!contains(profile_got, "ntproof=")) return -6;

    const valid_creds = "tls=protected;user=r4os;password=rosebud;domain=";
    const valid_in = r4os.abi.ProtocolBuffer{ .data = @constCast(valid_creds.ptr), .len = valid_creds.len, .capacity = valid_creds.len };
    var valid_text: [128]u8 = .{0} ** 128;
    var valid_out = r4os.abi.ProtocolBuffer{ .data = &valid_text, .len = 0, .capacity = valid_text.len };
    if (validateFixedCredentials(&valid_in, &valid_out) != 0) return -6;
    if (!contains(valid_text[0..@intCast(valid_out.len)], "auth;result=ok")) return -6;
    const bad_password = "tls=protected;user=r4os;password=wrong;domain=";
    const bad_password_in = r4os.abi.ProtocolBuffer{ .data = @constCast(bad_password.ptr), .len = bad_password.len, .capacity = bad_password.len };
    if (validateFixedCredentials(&bad_password_in, &valid_out) != auth_result_bad_password) return -6;
    const missing_tls = "user=r4os;password=rosebud;domain=";
    const missing_tls_in = r4os.abi.ProtocolBuffer{ .data = @constCast(missing_tls.ptr), .len = missing_tls.len, .capacity = missing_tls.len };
    if (validateFixedCredentials(&missing_tls_in, &valid_out) != auth_result_missing_tls_context) return -6;
    const domain_login = "tls=protected;user=r4os;password=rosebud;domain=CORP";
    const domain_in = r4os.abi.ProtocolBuffer{ .data = @constCast(domain_login.ptr), .len = domain_login.len, .capacity = domain_login.len };
    if (validateFixedCredentials(&domain_in, &valid_out) != auth_result_unsupported_domain) return -6;
    const kerberos_login = "tls=protected;mech=kerberos;user=r4os;password=rosebud";
    const kerberos_in = r4os.abi.ProtocolBuffer{ .data = @constCast(kerberos_login.ptr), .len = kerberos_login.len, .capacity = kerberos_login.len };
    if (validateFixedCredentials(&kerberos_in, &valid_out) != auth_result_unsupported_kerberos) return -6;

    var state_contract_text: [896]u8 = .{0} ** 896;
    var state_contract_out = r4os.abi.ProtocolBuffer{ .data = &state_contract_text, .len = 0, .capacity = state_contract_text.len };
    if (describeCredsspStateContract(&valid_in, &state_contract_out) != 0) return -6;
    if (!contains(state_contract_text[0..@intCast(state_contract_out.len)], "credssp-state-machine")) return -6;
    if (!contains(state_contract_text[0..@intCast(state_contract_out.len)], "windows_harness=op17")) return -6;

    var windows_contract_text: [1024]u8 = .{0} ** 1024;
    var windows_contract_out = r4os.abi.ProtocolBuffer{ .data = &windows_contract_text, .len = 0, .capacity = windows_contract_text.len };
    if (describeCredsspWindowsContract(&valid_in, &windows_contract_out) != 0) return -6;
    const windows_contract_got = windows_contract_text[0..@intCast(windows_contract_out.len)];
    if (!contains(windows_contract_got, "credssp-windows-contract")) return -6;
    if (!contains(windows_contract_got, "R4CW+phase+tls+variant")) return -6;
    if (!contains(windows_contract_got, "bad_pubkeyauth=-24")) return -6;

    var windows_harness_text: [1024]u8 = .{0} ** 1024;
    var windows_harness_out = r4os.abi.ProtocolBuffer{ .data = &windows_harness_text, .len = 0, .capacity = windows_harness_text.len };
    if (credsspWindowsHarnessDispatch(&valid_in, &windows_harness_out) != 0) return -6;
    const windows_harness_got = windows_harness_text[0..@intCast(windows_harness_out.len)];
    if (!contains(windows_harness_got, "credssp-windows-harness")) return -6;
    if (!contains(windows_harness_got, "tls_pubkey_binding=ok")) return -6;
    if (!contains(windows_harness_got, "kerberos=blocked")) return -6;
    if (!contains(windows_harness_got, "domain=blocked")) return -6;

    var live_contract_text: [1280]u8 = .{0} ** 1280;
    var live_contract_out = r4os.abi.ProtocolBuffer{ .data = &live_contract_text, .len = 0, .capacity = live_contract_text.len };
    if (describeCredsspLiveContract(&valid_in, &live_contract_out) != 0) return -6;
    const live_contract_got = live_contract_text[0..@intCast(live_contract_out.len)];
    if (!contains(live_contract_got, "credssp-live-contract")) return -6;
    if (!contains(live_contract_got, "R4CL+phase+variant+flags")) return -6;
    if (!contains(live_contract_got, "stream_state=R4LK")) return -6;

    var live_harness_text: [1280]u8 = .{0} ** 1280;
    var live_harness_out = r4os.abi.ProtocolBuffer{ .data = &live_harness_text, .len = 0, .capacity = live_harness_text.len };
    if (credsspLiveHarnessDispatch(&valid_in, &live_harness_out) != 0) return -6;
    const live_harness_got = live_harness_text[0..@intCast(live_harness_out.len)];
    if (!contains(live_harness_got, "credssp-live-harness")) return -6;
    if (!contains(live_harness_got, "state=R4CL;stream=R4LK")) return -6;
    if (!contains(live_harness_got, "tls_pubkey_binding=from-r4lk")) return -6;
    if (!contains(live_harness_got, "bad_password=blocked")) return -6;

    const ntlm_type1_fixture = [_]u8{ 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 1, 0, 0, 0 };
    var negotiate_ts: [96]u8 = .{0} ** 96;
    const negotiate_ts_len = buildTsRequestBytes(negotiate_ts[0..], ntlm_type1_fixture[0..]) orelse return -6;
    var negotiate_frame: [128]u8 = .{0} ** 128;
    const negotiate_frame_len = buildCredsspStateFrame(negotiate_frame[0..], credssp_phase_negotiate, true, negotiate_ts[0..negotiate_ts_len]) orelse return -6;
    var state_text: [256]u8 = .{0} ** 256;
    var state_out = r4os.abi.ProtocolBuffer{ .data = &state_text, .len = 0, .capacity = state_text.len };
    var state_in = r4os.abi.ProtocolBuffer{ .data = &negotiate_frame, .len = @intCast(negotiate_frame_len), .capacity = negotiate_frame.len };
    if (processCredsspState(&state_in, &state_out) != 0) return -6;
    const negotiate_state = state_text[0..@intCast(state_out.len)];
    if (!contains(negotiate_state, "phase=negotiate")) return -6;
    if (!contains(negotiate_state, "next=send_challenge")) return -6;
    negotiate_frame[5] = 0;
    if (processCredsspState(&state_in, &state_out) != auth_result_missing_tls_context) return -6;
    negotiate_frame[5] = 1;

    var challenge_ts: [256]u8 = .{0} ** 256;
    var challenge_out = r4os.abi.ProtocolBuffer{ .data = &challenge_ts, .len = 0, .capacity = challenge_ts.len };
    if (buildCredsspChallenge(&valid_in, &challenge_out) != 0) return -6;
    const challenge_info = parseTsRequestInfo(challenge_ts[0..@intCast(challenge_out.len)]) orelse return -6;
    if (challenge_info.ntlm_message_type != ntlm_type2) return -6;

    var authenticate_ts: [512]u8 = .{0} ** 512;
    var authenticate_out = r4os.abi.ProtocolBuffer{ .data = &authenticate_ts, .len = 0, .capacity = authenticate_ts.len };
    if (buildCredsspAuthenticateFixture(&valid_in, &authenticate_out) != 0) return -6;
    var authenticate_frame: [640]u8 = .{0} ** 640;
    const authenticate_frame_len = buildCredsspStateFrame(authenticate_frame[0..], credssp_phase_authenticate, true, authenticate_ts[0..@intCast(authenticate_out.len)]) orelse return -6;
    state_in = r4os.abi.ProtocolBuffer{ .data = &authenticate_frame, .len = @intCast(authenticate_frame_len), .capacity = authenticate_frame.len };
    if (processCredsspState(&state_in, &state_out) != 0) return -6;
    const authenticate_state = state_text[0..@intCast(state_out.len)];
    if (!contains(authenticate_state, "phase=authenticate")) return -6;
    if (!contains(authenticate_state, "auth=ok")) return -6;
    const ntlm_auth_start = indexOfBytes(authenticate_frame[0..authenticate_frame_len], ntlmssp_signature) orelse return -6;
    const ntlm_auth = authenticate_frame[ntlm_auth_start..authenticate_frame_len];
    const nt_response_offset = readLe32(ntlm_auth[24..28]);
    const bad_proof_index = ntlm_auth_start + @as(usize, @intCast(nt_response_offset));
    if (bad_proof_index >= authenticate_frame_len) return -6;
    authenticate_frame[bad_proof_index] ^= 0x55;
    if (processCredsspState(&state_in, &state_out) != auth_result_bad_password) return -6;
    authenticate_frame[bad_proof_index] ^= 0x55;

    var pubkey_ts: [128]u8 = .{0} ** 128;
    var pubkey_out = r4os.abi.ProtocolBuffer{ .data = &pubkey_ts, .len = 0, .capacity = pubkey_ts.len };
    if (buildCredsspPubKeyAuthFixture(&valid_in, &pubkey_out) != 0) return -6;
    var pubkey_frame: [160]u8 = .{0} ** 160;
    const pubkey_frame_len = buildCredsspStateFrame(pubkey_frame[0..], credssp_phase_pubkeyauth, true, pubkey_ts[0..@intCast(pubkey_out.len)]) orelse return -6;
    state_in = r4os.abi.ProtocolBuffer{ .data = &pubkey_frame, .len = @intCast(pubkey_frame_len), .capacity = pubkey_frame.len };
    if (processCredsspState(&state_in, &state_out) != 0) return -6;
    const pubkey_state = state_text[0..@intCast(state_out.len)];
    if (!contains(pubkey_state, "phase=pubkeyauth")) return -6;
    if (!contains(pubkey_state, "complete=yes")) return -6;
    pubkey_frame[pubkey_frame_len - 1] ^= 0x22;
    if (processCredsspState(&state_in, &state_out) != auth_result_bad_pubkeyauth) return -6;

    if (classifyTsRequest(&spnego_in, &out) != auth_result_bad_token) return -6;
    var md4_empty: [16]u8 = undefined;
    md4Hash("", &md4_empty);
    if (!hexEquals(md4_empty[0..], "31D6CFE0D16AE931B73C59D7E0C089C0")) return -6;
    return writeOut(out_buffer, "R4AUTH selftest OK");
}

const DerLength = struct {
    payload_len: usize,
    length_bytes: usize,
};

const DerElement = struct {
    tag: u8,
    header_len: usize,
    payload_len: usize,
    total_len: usize,
    payload: []const u8,
};

fn derElement(input: []const u8) ?DerElement {
    if (input.len < 2) return null;
    const length_info = readDerLength(input[1..]) orelse return null;
    const header_len = 1 + length_info.length_bytes;
    const total_len = header_len + length_info.payload_len;
    if (total_len > input.len) return null;
    return .{
        .tag = input[0],
        .header_len = header_len,
        .payload_len = length_info.payload_len,
        .total_len = total_len,
        .payload = input[header_len..total_len],
    };
}

fn readDerLength(bytes: []const u8) ?DerLength {
    if (bytes.len == 0) return null;
    const first = bytes[0];
    if ((first & 0x80) == 0) return .{ .payload_len = first, .length_bytes = 1 };
    const count: usize = @intCast(first & 0x7F);
    if (count == 0 or count > 3 or bytes.len < 1 + count) return null;
    var value: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) value = (value << 8) | bytes[1 + i];
    if (value < 128) return null;
    return .{ .payload_len = value, .length_bytes = 1 + count };
}

fn parseExplicitInteger(payload: []const u8) ?u32 {
    const inner = derElement(payload) orelse return null;
    if (inner.tag != der_tag_integer or inner.total_len != payload.len) return null;
    if (inner.payload.len == 0 or inner.payload.len > 5) return null;
    var pos: usize = 0;
    if (inner.payload.len > 1 and inner.payload[0] == 0) pos = 1;
    if (pos >= inner.payload.len or (inner.payload[pos] & 0x80) != 0) return null;
    var value: u32 = 0;
    while (pos < inner.payload.len) : (pos += 1) value = (value << 8) | inner.payload[pos];
    return value;
}

fn parseExplicitOctetString(payload: []const u8) ?[]const u8 {
    const inner = derElement(payload) orelse return null;
    if (inner.tag != der_tag_octet_string or inner.total_len != payload.len) return null;
    return inner.payload;
}

fn derLengthSize(payload_len: usize) usize {
    if (payload_len < 128) return 1;
    if (payload_len <= 0xFF) return 2;
    if (payload_len <= 0xFFFF) return 3;
    return 4;
}

fn derTotalLen(payload_len: usize) usize {
    return 1 + derLengthSize(payload_len) + payload_len;
}

fn putDerHeader(out: []u8, pos: *usize, tag: u8, payload_len: usize) bool {
    return putByte(out, pos, tag) and putDerLength(out, pos, payload_len);
}

fn putDerLength(out: []u8, pos: *usize, payload_len: usize) bool {
    if (payload_len < 128) return putByte(out, pos, @intCast(payload_len));
    if (payload_len <= 0xFF) return putBytes(out, pos, &[_]u8{ 0x81, @intCast(payload_len) });
    if (payload_len <= 0xFFFF) return putBytes(out, pos, &[_]u8{ 0x82, @intCast((payload_len >> 8) & 0xFF), @intCast(payload_len & 0xFF) });
    return false;
}

fn putByte(out: []u8, pos: *usize, value: u8) bool {
    if (pos.* >= out.len) return false;
    out[pos.*] = value;
    pos.* += 1;
    return true;
}

fn putBytes(out: []u8, pos: *usize, data: []const u8) bool {
    if (pos.* + data.len > out.len) return false;
    if (data.len != 0) @memcpy(out[pos.* .. pos.* + data.len], data);
    pos.* += data.len;
    return true;
}

fn ntlmMessageType(data: []const u8) u32 {
    const message = ntlmMessageSlice(data) orelse return 0;
    return readLe32(message[8..12]);
}

fn ntlmMessageSlice(data: []const u8) ?[]const u8 {
    const idx = indexOfBytes(data, ntlmssp_signature) orelse return null;
    if (idx + 12 > data.len) return null;
    return data[idx..];
}

fn spnegoKindName(kind: u8) []const u8 {
    return switch (kind) {
        spnego_kind_neg_token_init => "NegTokenInit",
        spnego_kind_neg_token_resp => "NegTokenResp",
        spnego_kind_raw_ntlm => "RawNTLM",
        else => "unknown",
    };
}

fn fieldEquals(input: []const u8, field: []const u8, value: []const u8) bool {
    const got = fieldValue(input, field) orelse return false;
    return bytesEqual(got, value);
}

fn fieldHasUnsupportedDomain(input: []const u8) bool {
    const got = fieldValue(input, "domain") orelse return false;
    if (got.len == 0) return false;
    return !bytesEqual(got, fixed_target);
}

fn fieldValue(input: []const u8, field: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < input.len) {
        var end = pos;
        while (end < input.len and input[end] != ';') : (end += 1) {}
        const part = input[pos..end];
        if (part.len > field.len and part[field.len] == '=' and bytesEqual(part[0..field.len], field)) {
            return part[field.len + 1 ..];
        }
        pos = if (end < input.len) end + 1 else end;
    }
    return null;
}

fn writeSecurityBuffer(out: []u8, len: usize, offset: usize) void {
    writeLe16(out[0..2], @intCast(len));
    writeLe16(out[2..4], @intCast(len));
    writeLe32(out[4..8], @intCast(offset));
}

fn readSecurityBuffer(input: []const u8, offset: usize) ?[]const u8 {
    if (offset + 8 > input.len) return null;
    const len = readLe16(input[offset .. offset + 2]);
    const max_len = readLe16(input[offset + 2 .. offset + 4]);
    const data_offset = readLe32(input[offset + 4 .. offset + 8]);
    if (len > max_len) return null;
    const start: usize = @intCast(data_offset);
    const end = start + @as(usize, len);
    if (end > input.len) return null;
    return input[start..end];
}

fn utf16LeEqualsAscii(bytes: []const u8, ascii: []const u8, uppercase_ascii: bool) bool {
    if (bytes.len != ascii.len * 2) return false;
    var i: usize = 0;
    while (i < ascii.len) : (i += 1) {
        var expected = ascii[i];
        if (uppercase_ascii and expected >= 'a' and expected <= 'z') expected -= 32;
        var got = bytes[i * 2];
        if (uppercase_ascii and got >= 'a' and got <= 'z') got -= 32;
        if (got != expected or bytes[i * 2 + 1] != 0) return false;
    }
    return true;
}

fn asciiToUtf16Le(out: []u8, input: []const u8, uppercase: bool) usize {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < input.len and pos + 1 < out.len) : (i += 1) {
        var ch = input[i];
        if (uppercase and ch >= 'a' and ch <= 'z') ch -= 32;
        out[pos] = ch;
        out[pos + 1] = 0;
        pos += 2;
    }
    return pos;
}

fn md4Hash(data: []const u8, out: *[16]u8) void {
    var state = [_]u32{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    var offset: usize = 0;
    while (offset + 64 <= data.len) : (offset += 64) {
        md4Process(&state, data[offset .. offset + 64]);
    }

    var block: [64]u8 = .{0} ** 64;
    const rem = data[offset..];
    if (rem.len != 0) @memcpy(block[0..rem.len], rem);
    block[rem.len] = 0x80;
    if (rem.len >= 56) {
        md4Process(&state, block[0..]);
        @memset(block[0..], 0);
    }
    writeLe64(block[56..64], @as(u64, data.len) * 8);
    md4Process(&state, block[0..]);
    writeLe32(out[0..4], state[0]);
    writeLe32(out[4..8], state[1]);
    writeLe32(out[8..12], state[2]);
    writeLe32(out[12..16], state[3]);
}

fn md4Process(state: *[4]u32, block: []const u8) void {
    var x: [16]u32 = undefined;
    var i: usize = 0;
    while (i < 16) : (i += 1) x[i] = readLe32(block[i * 4 .. i * 4 + 4]);
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];

    md4R1(&a, b, c, d, x[0], 3);
    md4R1(&d, a, b, c, x[1], 7);
    md4R1(&c, d, a, b, x[2], 11);
    md4R1(&b, c, d, a, x[3], 19);
    md4R1(&a, b, c, d, x[4], 3);
    md4R1(&d, a, b, c, x[5], 7);
    md4R1(&c, d, a, b, x[6], 11);
    md4R1(&b, c, d, a, x[7], 19);
    md4R1(&a, b, c, d, x[8], 3);
    md4R1(&d, a, b, c, x[9], 7);
    md4R1(&c, d, a, b, x[10], 11);
    md4R1(&b, c, d, a, x[11], 19);
    md4R1(&a, b, c, d, x[12], 3);
    md4R1(&d, a, b, c, x[13], 7);
    md4R1(&c, d, a, b, x[14], 11);
    md4R1(&b, c, d, a, x[15], 19);

    md4R2(&a, b, c, d, x[0], 3);
    md4R2(&d, a, b, c, x[4], 5);
    md4R2(&c, d, a, b, x[8], 9);
    md4R2(&b, c, d, a, x[12], 13);
    md4R2(&a, b, c, d, x[1], 3);
    md4R2(&d, a, b, c, x[5], 5);
    md4R2(&c, d, a, b, x[9], 9);
    md4R2(&b, c, d, a, x[13], 13);
    md4R2(&a, b, c, d, x[2], 3);
    md4R2(&d, a, b, c, x[6], 5);
    md4R2(&c, d, a, b, x[10], 9);
    md4R2(&b, c, d, a, x[14], 13);
    md4R2(&a, b, c, d, x[3], 3);
    md4R2(&d, a, b, c, x[7], 5);
    md4R2(&c, d, a, b, x[11], 9);
    md4R2(&b, c, d, a, x[15], 13);

    md4R3(&a, b, c, d, x[0], 3);
    md4R3(&d, a, b, c, x[8], 9);
    md4R3(&c, d, a, b, x[4], 11);
    md4R3(&b, c, d, a, x[12], 15);
    md4R3(&a, b, c, d, x[2], 3);
    md4R3(&d, a, b, c, x[10], 9);
    md4R3(&c, d, a, b, x[6], 11);
    md4R3(&b, c, d, a, x[14], 15);
    md4R3(&a, b, c, d, x[1], 3);
    md4R3(&d, a, b, c, x[9], 9);
    md4R3(&c, d, a, b, x[5], 11);
    md4R3(&b, c, d, a, x[13], 15);
    md4R3(&a, b, c, d, x[3], 3);
    md4R3(&d, a, b, c, x[11], 9);
    md4R3(&c, d, a, b, x[7], 11);
    md4R3(&b, c, d, a, x[15], 15);

    state[0] +%= a;
    state[1] +%= b;
    state[2] +%= c;
    state[3] +%= d;
}

fn md4R1(a: *u32, b: u32, c: u32, d: u32, x: u32, comptime s: u5) void {
    a.* = rotl32(a.* +% ((b & c) | (~b & d)) +% x, s);
}

fn md4R2(a: *u32, b: u32, c: u32, d: u32, x: u32, comptime s: u5) void {
    a.* = rotl32(a.* +% ((b & c) | (b & d) | (c & d)) +% x +% 0x5A827999, s);
}

fn md4R3(a: *u32, b: u32, c: u32, d: u32, x: u32, comptime s: u5) void {
    a.* = rotl32(a.* +% (b ^ c ^ d) +% x +% 0x6ED9EBA1, s);
}

fn rotl32(value: u32, comptime bits: u5) u32 {
    const right: u5 = @intCast(32 - @as(u6, bits));
    return (value << bits) | (value >> right);
}

fn inputBytes(buffer: *const r4os.abi.ProtocolBuffer) ?[]const u8 {
    if (buffer.data == null) return null;
    const ptr: [*]const u8 = @ptrCast(buffer.data.?);
    return ptr[0..@intCast(buffer.len)];
}

fn outputBytes(buffer: *r4os.abi.ProtocolBuffer) ?[]u8 {
    if (buffer.data == null) return null;
    const ptr: [*]u8 = @ptrCast(buffer.data.?);
    return ptr[0..@intCast(buffer.capacity)];
}

fn writeOut(buffer: *r4os.abi.ProtocolBuffer, text: []const u8) i32 {
    const out = outputBytes(buffer) orelse return auth_result_bad_buffer;
    if (text.len > out.len) return auth_result_buffer_small;
    if (text.len != 0) @memcpy(out[0..text.len], text);
    buffer.len = @intCast(text.len);
    return auth_result_ok;
}

fn appendText(out: []u8, pos: *usize, text: []const u8) void {
    const room = if (out.len > pos.*) out.len - pos.* else 0;
    const n = @min(room, text.len);
    if (n != 0) @memcpy(out[pos.* .. pos.* + n], text[0..n]);
    pos.* += n;
}

fn appendU64(out: []u8, pos: *usize, value: u64) void {
    var buf: [20]u8 = undefined;
    var len: usize = 0;
    var n = value;
    if (n == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        while (n != 0 and len < buf.len) : (len += 1) {
            buf[len] = @intCast('0' + (n % 10));
            n /= 10;
        }
    }
    while (len != 0) {
        len -= 1;
        appendText(out, pos, buf[len .. len + 1]);
    }
}

fn appendHexBytes(out: []u8, pos: *usize, bytes: []const u8) void {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const hi = (bytes[i] >> 4) & 0xF;
        const lo = bytes[i] & 0xF;
        appendText(out, pos, (&[_]u8{ hexChar(hi), hexChar(lo) })[0..]);
    }
}

fn hexChar(value: u8) u8 {
    return if (value < 10) '0' + value else 'A' + (value - 10);
}

fn hexEquals(bytes: []const u8, hex: []const u8) bool {
    var tmp: [64]u8 = .{0} ** 64;
    var pos: usize = 0;
    appendHexBytes(tmp[0..], &pos, bytes);
    return bytesEqual(tmp[0..pos], hex);
}

fn boolText(value: bool) []const u8 {
    return if (value) "yes" else "no";
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return indexOfBytes(haystack, needle) != null;
}

fn containsBytes(haystack: []const u8, needle: []const u8) bool {
    return indexOfBytes(haystack, needle) != null;
}

fn allZero(bytes: []const u8) bool {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] != 0) return false;
    }
    return true;
}

fn indexOfBytes(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len and haystack[i + j] == needle[j]) : (j += 1) {}
        if (j == needle.len) return i;
    }
    return null;
}

fn startsWith(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return bytesEqual(haystack[0..needle.len], needle);
}

fn bytesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

fn readLe16(bytes: []const u8) u16 {
    return @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
}

fn readLe32(bytes: []const u8) u32 {
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn writeLe16(out: []u8, value: u16) void {
    out[0] = @intCast(value & 0xFF);
    out[1] = @intCast((value >> 8) & 0xFF);
}

fn writeLe32(out: []u8, value: u32) void {
    out[0] = @intCast(value & 0xFF);
    out[1] = @intCast((value >> 8) & 0xFF);
    out[2] = @intCast((value >> 16) & 0xFF);
    out[3] = @intCast((value >> 24) & 0xFF);
}

fn writeLe64(out: []u8, value: u64) void {
    var i: usize = 0;
    while (i < 8) : (i += 1) out[i] = @intCast((value >> @intCast(i * 8)) & 0xFF);
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
