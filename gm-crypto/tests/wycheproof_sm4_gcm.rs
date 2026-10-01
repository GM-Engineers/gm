//! Wycheproof SM4-GCM Known Answer Tests.
//!
//! Source: C2SP Wycheproof `sm4_gcm_test.json` (testvectors_v1/), transcribed
//! into `gmssl-master/tests/sm4_gcmtest.h` and re-embedded here for Rust.
//! All 104 vectors are Apache-2.0-licensed (Wycheproof), via the GmSSL project.
//!
//! Test scope: 65 of 104 vectors have 12-byte IVs (matching gm-crypto's
//! SM4_GCM_NONCE_LENGTH = 12 API constraint). Of those, 38 are expected
//! to encrypt+decrypt successfully (`WycheproofResult::Valid`) and 27 are
//! expected to fail decrypt (`WycheproofResult::Invalid`, all `ModifiedTag`
//! with single/double/all-bit flips).
//!
//! The other 39 vectors have IV lengths other than 12 bytes:
//! - 2 `ZeroLengthIv` (invalid per Wycheproof)
//! - 12 `SmallIv` (1/2/4/6/8/10 bytes — valid in Wycheproof because GHASH
//!   key derivation supports 1..2^64-1 byte IVs)
//! - 25 `LongIv`/`SpecialCase`/`CounterWrap` (15/16/20/32/64/128/257 bytes)
//!
//! gm-crypto's `encrypt_gcm` API contractually accepts only 12-byte nonces
//! (NIST SP 800-38D §5.2.1.2 recommended IV length); these 39 vectors would
//! fail the length check before any crypto runs. A separate test
//! `wycheproof_sm4_gcm_rejects_non_12b_iv` asserts this contract.

use gm_crypto::sm4::Sm4Cipher;

/// Wycheproof test-vector result flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WycheproofResult {
    /// Vector must encrypt to the given ct/tag AND decrypt back to msg.
    Valid,
    /// Vector's tag is corrupted; `decrypt_gcm` must return `Err`.
    Invalid,
}

/// One Wycheproof SM4-GCM test vector (12-byte-IV subset).
struct WycheproofVector {
    tc_id: u32,
    /// Wycheproof flag string ("Ktv", "Pseudorandom", "ModifiedTag", "SpecialCase")
    flags: &'static str,
    /// Wycheproof free-text comment ("Flipped bit 0 in tag", etc.).
    comment: &'static str,
    /// Hex-encoded key (16 bytes → 32 hex chars).
    key: &'static str,
    /// Hex-encoded IV (12 bytes → 24 hex chars).
    iv: &'static str,
    /// Hex-encoded additional data (variable length, may be empty).
    aad: &'static str,
    /// Hex-encoded plaintext (variable length, may be empty).
    msg: &'static str,
    /// Hex-encoded expected ciphertext (variable length, may be empty).
    ct: &'static str,
    /// Hex-encoded expected authentication tag (always 16 bytes).
    tag: &'static str,
    result: WycheproofResult,
}

// 65 12-byte-IV vectors from the Wycheproof SM4-GCM suite (tc_id 1..65 of the
// 104-entry Wycheproof SM4-GCM suite; the 39 non-12B-IV vectors are out of
// scope per gm-crypto's SM4_GCM_NONCE_LENGTH = 12 API constraint).
const VECTORS_12B_IV: &[WycheproofVector] = &[
    WycheproofVector {
        tc_id: 1,
        flags: "Ktv",
        comment: "RFC 8998 A.1 / GB/T 36624 C.5-equivalent",
        key: "0123456789abcdeffedcba9876543210",
        iv: "00001234567800000000abcd",
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        msg: "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
        ct: "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d",
        tag: "83de3541e4c2b58177e065a9bf7b62ec",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 2,
        flags: "Pseudorandom",
        comment: "",
        key: "bedcfb5a011ebc84600fcb296c15af0d",
        iv: "438a547a94ea88dce46c6c85",
        aad: "",
        msg: "",
        ct: "",
        tag: "a486a45596cb92cf529de2038583707d",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 3,
        flags: "Pseudorandom",
        comment: "",
        key: "384ea416ac3c2f51a76e7d8226346d4e",
        iv: "b30c084727ad1c592ac21d12",
        aad: "",
        msg: "35",
        ct: "a3",
        tag: "a06f50a378b116e9dd2363a6e8babd88",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 4,
        flags: "Pseudorandom",
        comment: "",
        key: "cae31cd9f55526eb038241fc44cac1e5",
        iv: "b5e006ded553110e6dc56529",
        aad: "",
        msg: "d10989f2c52e94ad",
        ct: "ae080aa27f476736",
        tag: "9e649f28d3f52a4bf7e3239a980617fd",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 5,
        flags: "Pseudorandom",
        comment: "",
        key: "dd6197cd63c963919cf0c273ef6b28bf",
        iv: "ecb0c42f7000ef0e6f95f24d",
        aad: "",
        msg: "4dcc1485365866e25ac3f2ca6aba97",
        ct: "8903a5225332b06e89bc1ad13e4406",
        tag: "41feccc33a5a27fab0883a11e4ba3b71",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 6,
        flags: "Pseudorandom",
        comment: "",
        key: "ffdf4228361ea1f8165852136b3480f7",
        iv: "0e1666f2dc652f7708fb8f0d",
        aad: "",
        msg: "25b12e28ac0ef6ead0226a3b2288c800",
        ct: "f18ce821bdf23c0e74e84a235ae15926",
        tag: "dd82022d2589c111d2f780965bd4b7ea",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 7,
        flags: "Pseudorandom",
        comment: "",
        key: "c15ed227dd2e237ecd087eaaaad19ea4",
        iv: "965ff6643116ac1443a2dec7",
        aad: "",
        msg: "fee62fde973fe025ad6b322dcdf3c63fc7",
        ct: "bec3d84d43648a235d8e2db8a61c3d9317",
        tag: "78372866def4d47c141dfa360ee73f8d",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 8,
        flags: "Pseudorandom",
        comment: "",
        key: "a8ee11b26d7ceb7f17eaa1e4b83a2cf6",
        iv: "fbbc04fd6e025b7193eb57f6",
        aad: "",
        msg: "c08f085e6a9e0ef3636280c11ecfadf0c1e72919ffc17eaf",
        ct: "33a7785516a033fef7e5b94bea7cb271ab176f8f1c853280",
        tag: "48d1f612fbf49cf11ea7e44c2d160770",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 9,
        flags: "Pseudorandom",
        comment: "",
        key: "28ff3def08179311e2734c6d1c4e2871",
        iv: "32bcb9b569e3b852d37c766a",
        aad: "c3",
        msg: "dfc61a20df8505b53e3cd59f25770d5018add3d6",
        ct: "cd6419e4b259e55f460f88763ed7229331ed11a0",
        tag: "e156c8364e952357442b9a372ebc2f1f",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 10,
        flags: "Pseudorandom",
        comment: "",
        key: "e63a43216c08867210e248859eb5e99c",
        iv: "9c3a4263d983456658aad4b1",
        aad: "834afdc5c737186b",
        msg: "b14da56b0462dc05b871fc815273ff4810f92f4b",
        ct: "74011a2daa5b32ff71fc8fdd8b6ac88f3ac34c96",
        tag: "7888f6f99acd94c4e7f919de632107dd",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 11,
        flags: "Pseudorandom",
        comment: "",
        key: "38449890234eb8afab0bbf82e2385454",
        iv: "33e90658416e7c1a7c005f11",
        aad: "4020855c66ac4595058395f367201c4c",
        msg: "f762776bf83163b323ca63a6b3adeac1e1357262",
        ct: "e701e87475f01be5593829ffbbc8c212324d1f33",
        tag: "0e6ef70f71cc450c2097481d6ae26b23",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 12,
        flags: "Pseudorandom",
        comment: "",
        key: "6a68671dfe323d419894381f85eb63fd",
        iv: "9f0d85b605711f34cd2a35ba",
        aad: "76eb5f147250fa3c12bff0a6e3934a0b16860cf11646773b",
        msg: "0fc67899c3f1bbe196d90f1eca3797389230aa37",
        ct: "e2ceb4ed26cad57080e1bf3104f3251c486395d6",
        tag: "00468fce2225bfea9b46679889cd1241",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 13,
        flags: "Pseudorandom",
        comment: "",
        key: "bb571c160132b0c8d5d190d0bc356ddc",
        iv: "2596c440cf0232950ec66bc4",
        aad: "",
        msg: "053be1b6190a717fc74c879e6fd62dc44628495507e50d662271dee795a4ad26e0c4f86cb6b20ac6bd9d682d2d8a05c9dad875a6911b49ea0af4f17c97a5f2",
        ct: "d02d6f100875eb876a1218e2282c7af496f9737e3653057074e28221b310d31abb705c01c03133171615e19b658edb9cf7bcfd37c5ff3ff53d88f854b7ff01",
        tag: "9cc97f0b5ed2f18cb703f9f791fb77b5",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 14,
        flags: "Pseudorandom",
        comment: "",
        key: "e12260fcd355a51a0d01bb1f6fa538c2",
        iv: "5dfc37366f5688275147d3f9",
        aad: "",
        msg: "d902deeab175c008329a33bfaccd5c0eb3a6a152a1510e7db04fa0aff7ce4288530db6a80fa7fea582aa7d46d7d56e708d2bb0c5edd3d26648d336c3620ea55e",
        ct: "3cf60068035b62a2f137f2066a26c2b3540ebc693f88eef83c6d665e4ecda89f39fa522a9f474f7f55eddad8458dc03193a41e9f0c42208ceb6b95f74e39edbc",
        tag: "f27df72c4b524b3f2eb5cbcc7aeebb21",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 15,
        flags: "Pseudorandom",
        comment: "",
        key: "97ec85a69a05131cd4ff643972f6d8f9",
        iv: "9189e0eedcc413a0ba1e63d2",
        aad: "",
        msg: "10acefa6f3959faecb5cfdaee8aaf09d4381b2b147e0b13450c26ee07f29edaa9a1f1af4e2d111dea7ff681a19fc3a4fd66df6a17985b06543a3b6c0e4e51a54b7",
        ct: "20453838c211ce33b536b65acf1d6709c867d45f0535719ebb983ab3dfa25389a6d6ee796256be4f5aed60c0759ea8eae9261db2885f16ae03076f1e39d40fcaa8",
        tag: "74c2c3f340557da5d5d1978e465baa4d",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 16,
        flags: "Pseudorandom",
        comment: "",
        key: "65d38f0b268f180d6ba548d509111dde",
        iv: "e14dfc27394ac846c2373ea7",
        aad: "",
        msg: "1fa76d7995dc996a5f5dabaa4be401be14f4d4706a213a4dd725df386ec147a6be074947c733094f47a7222552376740aa8348a0ae1c7f2d972a0ad664f8b8ec81dfc9af078b61daea5dde874fd73775b4cd65acf069ada0b2b9bfbb4a9817ba41d4dcaff7653df5c8cd9ce7f59eec92ae9e61314e03ef48839810ea825520",
        ct: "8ebb80a490915d0029cd86349723b590aebad5e561fb585f9310a0fd676dec2c320fd5dd4488e2f8ec6d0fe6dcfed01442840c57226495cfe2bc7b501505ad02f2c85b7263c844ea4b1de6b4a31931416a734cc10a1d03a105aa7276cbfb6b488bd45b88c851d96f2803bc00a973e070cdd5fcab727e9e7bc893113e75e1fc",
        tag: "4ae233941ee9c41b6a98735150511f43",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 17,
        flags: "Pseudorandom",
        comment: "",
        key: "3c55f88e9faa0d68ab50d02b47161276",
        iv: "d767c48d2037b4bd2c231bbd",
        aad: "",
        msg: "5d6add48e7a5704e54f9c2829a9b4283dce0d3a65b133eba3793c4fbfa1d8e3a2539d0d4f3de381598ce5b2360173fbd149476c31692c5d6e872fce40219378949c2e70b5f1b9f0a1d5f38352ad814b2a035bb3f3f26425d831a2f7a5e65c5dfcd91a315c2b24f53a662605ea40857dd980e9be5cdad000c569f2d204d4bd3b0",
        ct: "c4097f82493606712bfa87962bdb55f8f6f5b2b955022dca6a1fce5ffae6141922d8aab5895051a7a2088e3b68daf0ac0109fbbccea34bd224558f98ccc9e08eaf154adc54cd10dfa1246401109c5b0e506f716691bfa6957b87a2869d63a4993fcbc06137daa5f75862868b9d72ab6d625594b517c87f3c851e62961fb40069",
        tag: "dd0fcfa94dd633a2c286a494c4c328b4",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 18,
        flags: "Pseudorandom",
        comment: "",
        key: "62b3881832d428b6f900cacfa0fc5cd8",
        iv: "f4cb98cc99e7bc424a98384e",
        aad: "",
        msg: "0b91dd36a6fa967a257b267d12cbc20b56ed615b205d044a04b4ae8aaa365bd29a3b8f47a0828ef63324d1ff924c68090abaaad78df602edee0621b823f94c35ada7b62d81f21dd9945d1abb4ef882cfab12c2e4cec705df3d669183fe681753503a99a871637953537ef479b1f62de7819dbb5c950de7722090942d38129aefa7",
        ct: "32f946b864244ae0180fe888e013b1c13c11d2705e51454239807b391a26c0cb34aee65225d7b23552007a8d9af1cc0dd453678c60c79fdf8550e5721ee82020ce00a78c53530922e2a4fea20a846209e074ed5ea14b42f5d76e57fe1f8e4fb00cf9fe5baf0510603c62e3b1b82171b4e80b54ca33f86717b8e7180bb5bc8307ef",
        tag: "7313b877c318b929701be999204940fe",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 19,
        flags: "Pseudorandom",
        comment: "",
        key: "8aeaa2591a452e626b9a6468b623bdfc",
        iv: "b90f446f68aea588d843d01a",
        aad: "",
        msg: "f0721c3b68d905092cada6d568df3a2da39573c7bb0e9a4ed159a2634237f9e788488c06fe8a7e1e01d1a1c985543ecf90f3d32e57d33c3df6c165b7edc6fbcf8bf2d043d1b7c0060309a29565a004ea3214d4e4f7dedeac2d74576c019b5fa000d025917af6f86310942102a34d92781972d4f1f57bbdd6f9b08cc979a358aacf6cb62334bfc916c249f18bcee644a8907ef576b41437098bdf0069767fb5ed1c0f1385e5895e4a5d70f5941a93014333436a7af465ec1038fdfa006410a0871225d64848e6c59ac23f176df663ee2171c9eaec0477f9ebd280880d9f2967a2e791cc998f6b23518ca97bbc6405d6ced3373ebf3d208c2a909274460a614a",
        ct: "183a6203422f02c1759b4ce9747189fc736bb5f0730c1925f608bd8b521fcb66e24dbd4981911e2d305940adbffe6809ffac7c255347e2cf7b4d55e38a00c989ffbf2de7a83f8788edde38a7f486a5e19540b937d65912522d4c9a852182e5c6cff6e893c89ca1e80c65af4befc5e4af1d3555657791e7bb81ec66fefaebde4157ab572675c4db01d5af1e3a8f0eeaa08058034a2ab64b0f55ac684f457dbf6157b22192a153d97ba55f1d6c0671de990c41d74eb9e4e8ded60e982bcfe3ae046f04004644228831ceb345ac1e09f8a2549c18e54fb47cabad38ab5be44a3ca0455378e12aa347dd0c83e1d996d129ae40009e9b69e6d50b28c4ce2462f478",
        tag: "48b78c532cb214b6ca30bfdd86f176fe",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 20,
        flags: "Pseudorandom",
        comment: "",
        key: "e88d95eabe88fcf158fae858af951221",
        iv: "a65834a9d231b34709383e9a",
        aad: "",
        msg: "2decaccc8b424fa4963890ece15b3fc281b6215780ff6baee57edcd25afe260ff80ed4f25cc04d2802a1e90a2e6e96d1ee73a4a53dcf60025d484054d146f275ab34c33b102001a07d804cc94a40fd78c16780d1b648487fac035386e5d25c2b9edbf7a52d102d1943958c009eb6d88e00a3227c4c788e445003fabb4dbefccd3fe1716d916446fee2111615d560ecc59d7bd288268ab321e7002545887183fe023fdec2a6d3b73b94d1548cee19638d31d2c5a32b15d2aae3f42950a787115e200b00022d4929105da0b4d10ccb0b3886b3169b32ac5df7a637c23362e2d4ed9c137f35bbd578c2cda0377e0f1e64f7d31e9ef4d7603ea1363523758385c761",
        ct: "a52eaa06d18b3a970dd6bffc6f7a82217682feaeff0cbf17f91754734bed11d7d287d46628e0d4bf4cfea03e5be768189d67bb060f89276a01421066bdd79549c203a2a3eeb5ade383ac810a9ce68c5a4ae8a540b9b7179acb8215b3f9e85600e4a826a6ae658ccecef802a6ae56a0eefc40915d91f7c33663baffde91991d6c07123853a17929985a925f609f87da4c63cb75ffc8dfc0c04e331236f3b19b6e6c2ec25cd85b639304812fe1080ca32d0b48581505070d7d2e4d104ca4f44f94957b8a2c9b180238eb0f2258c9f434f1f8c5731dfe32faaf827c2621a8cac4a0c11f06bcdc3d60a6a02bf27b76e963cac986019ac10d9630a1c1f870167f0f5f",
        tag: "66a8c169caa97cd1f37949227fd1fb93",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 21,
        flags: "Pseudorandom",
        comment: "",
        key: "a294e70fa2ac10a1fb00c588b888b673",
        iv: "dfe20d1c4350e6235d987af1",
        aad: "",
        msg: "6ed1d7d618d158741f52078006f28494ba72a2454f27160ae8722793fcebc538ebc2f67c3ace3e0fe7c47b9e74e081182b47c930144e3fc80d0ad50611c3afcfe2dbc5279edbbba087c0e390355f3daffcd25ad4dea007c284ad92e7fcbecb438fb60623ff89a599dca2aac141b26651386ca55b739b94901ef6db609c344d8acf4544568e31bb09361112754b1c0c6a3c875bd9453b0ee0081412151398a294ecad75add521611db5288b60ac3c0128f6e94366b69e659e6aa66f058a3a3571064edbb0f05c11e5dde938fb46c3935dd5193a4e5664688f0ae67c29b7cc49a7963140f82e311a20c98cd34fbcab7b4b515ae86557e62099e3fc37b9595c85a75c",
        ct: "16b2dd02d544d31db9200d4c426f958dfe6e7a5e7a15e12282a4926333b819991e152bcc086badfe7e660272ee6385256a27adef22d6bb937d0c8360114f0cfa2b53f1de18cfab5ff72369989ecbd30f302713a78be5e40ac04f07dd9230fa1cb92767920e053c0fa8da1552391ca82348ff2e6a4d34945205e08e0d530c43c3f93378a75de624dfb4a83e51ab439a5491c931de76d9525025daacb8ee33af056877bbb1304137799c556ae5c4a3e33987735704f391dbf777130f01e3f3a652a83f120c52bc2ca0d9942429e1aea2fb407e19ddb5116bb4cb91a15b5d0911b090e87f1bc452c6fff1c27df884d1b009f27dfaf80b8be4e9fc5744f06b927c423c",
        tag: "a48829706402c1c2bd33d72af6ec0746",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 22,
        flags: "Pseudorandom",
        comment: "",
        key: "4a30eac07b788b7354a90e6448f56676",
        iv: "c359d567616b6384ac20a43f",
        aad: "",
        msg: "9a17b9d1dbe666f7431cbdd3b3173948c7ac13f268e12807256d2e5831ae67a14116144910b38368934571daff9d4004ba959b3cae2669e6eed49e750ca228415c6f7d1c1f2d3dbb02f4dfa49483a7f80fbcc1cb01d22c67817cc7a2bd2714eb62cdf8fb884a66ed245167cdb22e0dbc7b153e648714dfe83414696cffa892daf5af8820d562bdf55f76be5584a34b7e349d10d76c6e68305835b551a41ebf48e068320d875334a6a2d3108b1e93f7aa8da485d7a5470d805e0dd38c09feaa0f494d0572de314a287439f48aee5a2fa8e9850c6127ee88d50c5e8a2ac3eaa7b2fdd1589813fb3affa6589831df132bd576fbed21717e2b6766e593ed74dab35da125c433763ea90234dc6f01d37be14c78b8861be1fb4c8296b3faee65b6ef8a9daa6884e936359346f2da9f6981f9d64f676767641ada628aa8c7129326bd4ee57e515a2f78ba18c595b9bc1d0f49068734a67e635554eee688816061e904a4e05125d0e7797305451a7c3a1a3c507daedb990c12ca290a0f554aa8e834653aa21a0469d3b0c08ee512b323cb193779c9fe2f2b3f03794cd42f0220031d0c8eeb9c73a3283a599bc78da3b5b41b243edf082b23801a15d9956fca60f35acfb65c4d06d28aff81a1ca98c6faf8645be920bd87c03c054a0469b292ae34d05860e8d9b061300370463dcd5fcd6fb1d6b1acc9b4eb25cabd9de4e61d44922fcc",
        ct: "ed332423927bc604bb52e049a1802780b9b33cc358df55a86f75ebd3e370b5e6b79435c969ae01683a819efe01dbb25242be895317ae381bb1d918ca0b62c679308da19919090706d7d955f47d2c091761e3fcb5744bd3095ae9b7f62dac05e6f258f4ee79bc258a89f9ba09a925476e1d34c0164d8394ff33778c0a2032f9453d30103dd0359089003c4fb36c7378965ef799d93121281b4e1d66cb17db91171ed338039bb7ce9cf1ee4d56cb591e3ffdfe425b55491556f3bd48df95b75134438df4a94ff9a155d499403ec6c4547beaa95e554188849fd8273ee301775eb3ad88d7a297a2aabc45af312e15f8103520599f155d389764308c8b277dc6773f23bcc2cc1f1b4086a10a78a258011f8030b48c741af6baa0ec7822d60d8706c768e2266ac0eb110fc2cbf55fda0fe3dacfd7dd4c966f5f23fc457c3c86bd5af7d08b283e7f0e0f58a68b1268575fe45a45c8da8c2f7f00e95e0263f2c1dfdf378697699b6d9dca82d0108ce8e8b3fa7f944b31df7701627497323e450aa54c2f884f6454ba23525242f2240bbe238746af4e4d4af6bf9d2ec605093ed0f6960a932a719d30c8fe1ffd04d294b007c29e60d289fd2b324653a8be4160f9aebbd0a24f64d37ff3efde79bf7db2d01dbf93b685b38a54d6c90bbef8ea90a6a2265790f30001047723ca8a8b9c7d11c645233a3effdb4d5ac86a2ec6b9559b81a5",
        tag: "8085f8f6b04a4ebd15588c7f753f6d32",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 23,
        flags: "Pseudorandom",
        comment: "",
        key: "fc8e6d2c7f42cab59375327285cc3398",
        iv: "49e1e00c48eaf1b5b9d2cb45",
        aad: "",
        msg: "2121b06990dcde2885739032622fd70294174074bffdf40b01f3554d5d87242da61673fe9b1687771ff1cc330d7b8a5138f6598d8160ec90a4816a6dbab310f2c99ab19c49d8a5d04eed4b93cd76159766548e136517ecfb6aa7ad51e5ff6d083c0e53533692388e651ea9cba94693118e4699926476fea785d2cac0213aa68ae0a366923532d333ef133b490a4667606f7294db8c6a4530407409b51e803493d46638fba151b2031f8208d595b4e4ae55db66cd7c328753cfa0f644438b0bff4f87d9b7c5648e5d2e8057e0b20d550cf1d0aa13900647c332909b50f8ecb1ee148342aac705b28215900030bfd90ca1446e3a03ceb2ab71a9ceb3d8f0b4626febf1dcff3c1f5ae0fef4c0f74623ba47eb5fdc42d42a2039f45e5987624d97d0fcfb95f74c478d613b9067f03cb86d6055d5124e6ff3174d136d60fd7a54e7c8fdfff20fb5807c4e356cbfc70df4bf83997855608558dff64b3ea8854481cb24933000489f4b8e9415b22237e916653874549d7687ae71b063ace3ef7e41c705d197c3157dacd3263d61132a4f07b91cb0cd79bc7cfd85f6f8c1f507c33bb910e2e879e0e4d8fedf804134d14d5998b38376d9ac0831d1577510ef3704e3f68acfcb433aa2a751f94fa8b6b312afbeea7f3d1f38784d79db414c7799e011ca4d35779ed17aed7d96df5e1a60ace74692686ede778dfb4beeb42585c8ccdf03cf",
        ct: "602667685844853997c8913dac2cbabfd85117403418156d6dd41d60e2f0fc54fcb0b7a4938f10c574c3a89e7814e8c9ff43967f341773f0cb346109775fd88833bccf032d5f89a62c6ad3beba1c54f19e560b705c83576e627d349075008f516e4e1f6a0bf6840e988dcd743c128e5450e55ce588d612ec998af015df7bdc6e3f540eb6c1477473042016a1b7a6eec4571ef26a1dda50953f2b64ade71c689763c7a397c53d964df4f6b029cf44cab8432bbaa88321920b58c64d86d8b61258599d79c4c142637a39e6445c533162d7a4b3d63a490f4e7eb96e02cdae91b845804144f8f4a45443fec4a4a768d3977d6b745e789853c652719dad975e5660462d08186b7dd45c25afe0622da971b7c77e5c22774b96bcfe63af515ee6e701f3d76223a43993d7c2587faa6d501548e586961dff3a189dd4a9ae89bfd1205cbb218d3a6116f6a9fe2259807e80bc1d431f04c78f5f8cfea3185752b1cba0dedc9edf2c8564b2da0e2f7a13aac657b91de6c7b92433982478adfcb16e24ba9d6d7b340d9dbadfcba215c30f52117eb7ed7395628dc701e6a0d2666446e49eb2cb95a64eb4ac66b405e5b15c249ab636fec0346c1bb2047b256f1cb246916f104898e0dbf7390f9bb7ed0e1c4ca0aed08bf8687bf68db2c920c655a0c366066ffe1352e4a8ac6d0725edf16f744de04533cb188910601fd0d9e85c2996944f8c5c",
        tag: "3fa8967be7b3e6d81ba003a065967893",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 24,
        flags: "Pseudorandom",
        comment: "",
        key: "f01a3c3559c58e80bc832544e069ef29",
        iv: "cd5bc2aed48c3be836d7d786",
        aad: "",
        msg: "0de5aac3f151b526751de8f36010e4394498eba3c8bc790fd4ba96eb2da33e40ddca3cb36fec102ef37a6a5132cd389bbcabbd15e1c9d2700af35f19a01ba3b26843ab50833f252befbbb5529173d51ca364d7d09468b3b68f740a6014b5b824206a6a7118bf144a223f87d76624c138bd24a5fa996f36e316087f3b59c1c71cd74a9184a518c8d9aa8c7243102dd39a93599e7bbe7dcd354d0780253767e9602f2f0cbbab7eae8d8c12cbad163f8fc20d32559f798d2b7285dba6f66dc28d9b3f0a301aa89f5cd1b5a1734fe72c68f98c861d26e7dddaa08a227999f7c98d7315e7c2e3c3f198cdd4cfd62f62389998c7b760106d0a437f5050f74f9ce63948f5494bed71c88be443654ef9eb0c867eede225c1bda181baabd8155360ccae65e54d399a3f7d670d11b53d7bbecda15d53e129ef2be29154e3c21411e6207977e2620007cf4b987dd2c304efe55bc2ef564074cd6e176a97184bff4cad0cd0cb85195c4e8398f27ca0d4d8c4851359eebdb606a213223903513f0db8c0fcc1f3a834738f6c9dd6adb43bdcbd921e7c3cd3b252e319f9e711edf55e8d7f1a320705a3ba77bfa33463a922a9f36b483590c4939fd977ace51c506d2e269b488a7169b696d828458ecb092ae3a9adf63a3a12809da51fc7340fc57db50fa1903f1c7de9ce606f1de3f95538823c04e3bfb6549385643710a2919f2fbd54887bdfb239",
        ct: "7f0653fb6d1523b46fac1705b042a42352d740c182398f329928e3c17c1359026ad60c9eb8cc6eafe25103715caa614b4f086c410318b9e316b0aa8dad7f8b163ef2800313de56eb5bda304b2cd03d2c6a051d1563db37c38bdb918d4998414f58b6e67569ae7f93363e3b3261c5a40ea8db07e7c496a2fc224be34b7fefb71cfac8f8bcccc7ebd95da3a46abbc248b2c3e7d7332d81261f1853185f92e36cb1e183e1cb23e3d1a3a9cc458c4e9a27f0694a4f3a7d090c76d8692d2fd154bed73023ca08fd2f50793b03f097cc46f4904f12a99cbb4da56051b8df27c75b0fadf087abd0c11f8fe4f31c338dd203ebd81eb22f24a9f93626fb2a49cbcdbc91a9c349d6629bef745bcbf1c7082a424efd21fa525ffbc8ce11a47750fa99ed70e981c1a0881d415dbfbb74801b343b822ca48a0d2b5e55e5ba27adb209fe764d933f2778b88e301730c0f251dcfe26424d79647fb74cb2caecff3132a2d36ca0150c52aace33b26d372fca9f3d67feb11104fc0f8eca0ff64b770eb852ca7344f2a500a7359ed69ff4b7e73709cf302cffed55b4d2ad14ea85359f1fc6618cb9503d74817cbf56a878a07b30a2193bd709a44c3527e6d3c2356c0a4b83b101eb07604b93fdc66f487927c10f77b3d45ca9ce576f8ab92df925a29444314b23e8908cc776d2b1b6314455d8159579c3bda6a72c14a05b6728b836bea42cdba7618557",
        tag: "d89e2bf8efbe0737db445f07309d6cf6",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 25,
        flags: "Pseudorandom",
        comment: "",
        key: "5a475f9976ed117ab37a4fffab0592eb",
        iv: "6bce45bea6ad59bd2a08f7b3",
        aad: "e8bb51b694b6b0763e097bad1152f5c762a878a3e7f7a9d78e809838de78567900281b7e4f0f185493fd85e28db79b595541aba7e158b3936490b632355d74",
        msg: "dc6ab0e261412cc709422289ea202021d9298060",
        ct: "e6075b0311d3b64a61770961dd76c848335c448f",
        tag: "1727a5e1836e0be8fe71c079d03e6953",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 26,
        flags: "Pseudorandom",
        comment: "",
        key: "c4b03435b91fc52e09eff27e4dc3fb42",
        iv: "5046e7e08f0747e1efccb09e",
        aad: "75fc9078b488e9503dcb568c882c9eec24d80b04f0958c82aac8484f025c90434148db8e9bfe29c7e071b797457cb1695a5e5a6317b83690ba0538fb11e325ca",
        msg: "8e887b224e8b89c82e9a641cf579e6879e1111c7",
        ct: "8a0751048ebe7340e2479bd7b86762a7dd2f9b98",
        tag: "917a9b8ff6fc5cc1a99902f7c85286d7",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 27,
        flags: "Pseudorandom",
        comment: "",
        key: "f64d1bc47b081afb21181bdc16ffbcca",
        iv: "2c03293704f79612181609d3",
        aad: "a883d23e25a62b492f1271d3d79b8689dde7250a0575b8175a6b69d48d1b4bc2df1b4dc4a2b1eb506bc0e8c11e7dc2f3d08b475214551df7c53e581ec55c0d0a2d",
        msg: "85b24904bf12ced33d78df7437b36fff83d1e817",
        ct: "9492109f394275211c07739d01ab6335cd61134f",
        tag: "f89ee2a739e6f78d2d27e9645cb26dcd",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 28,
        flags: "Pseudorandom",
        comment: "",
        key: "7e0e0cf8c9ac58867ef3e3315d0a4338",
        iv: "a03461bd9ffedb16a65c0389",
        aad: "c70f009be65ade8465cc05b5227963c12c60b68247ae2e431b2445bb6aa69c0a7820177861e5f6e3585269fd15efaf38c3713e6af0e93362d2d9a6e3296712f581563ae3980298f8bb7276859afecc7052fef63b060bc8f219ffe200e14dbde1f0a36233b5994a0b68c4690b437d495ddff991993e75039bcba4c19d7a6f01",
        msg: "de4451316ad820471a43906965af9fa221c0360f",
        ct: "4f8a5742201cedcc79665375acddaaa93c2b4598",
        tag: "f98c8d232ab7a971d9786340259fdef6",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 29,
        flags: "Pseudorandom",
        comment: "",
        key: "7e37d56e6b1d0172d40d64d6111dd424",
        iv: "517c55c2ec9bfea90addc2bd",
        aad: "8ed8a9be4c3d32a5098434ee5c0c4fc20f78ef5e25ed8b72a840a463e36b67b881e048b5e49f515b2541ad5ce4ebb3a917c16bcdc0dc3cb52bb4ed5a1dffcf1e1866544e8db103b2ad99c6fa6e7de1d8b45bff57ec872f1cfc78b0e4870f6f200ff1291cae033defc3327ba82792ba438e35c4bfbb684fec5ce5e3ae167d01d7",
        msg: "6a7dea03c1bba70be8c73da47d5ee06d72a27430",
        ct: "3e3952e03cea4089e749c8245a1bb3f57ae4d327",
        tag: "dc7034d362140aa697ac921b3ae79dec",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 30,
        flags: "Pseudorandom",
        comment: "",
        key: "d9218931dc592aef3bffb924c9e0b02c",
        iv: "17d824f4f2f191e9c9dc0a52",
        aad: "76dcb9948575b503fea75cb3d4949bb96ae3d2c1780f185e0fb3cd5b83eb7090be7a966f6146a4db7ef82f8adb9b10158b69d4bb19dffe4c639fe278d0334e68aaf1b68451a8e6778ddbb29aac4b25bcb2ea059601ee2eba439134aecd0ceacd98e388c40114c11969dfd4a16beeaf3d1c7410e99e674894445821e8fcda7b7ba7",
        msg: "29f29bfc5b09ff158d74fbf7532c06aa3afa936c",
        ct: "f225532f67bf05ebf64a9598eb8c340cd0a29d17",
        tag: "be3856c36aae137a8df93cbfc2a35a61",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 31,
        flags: "Pseudorandom",
        comment: "",
        key: "bf2056baaf45c5a00a733b49f10b7dd0",
        iv: "fef1b243b44ba92b47c6626b",
        aad: "1bb3a17907279ebff63593de97a64e5ceaf9e1d407e5a5eec1ce0f62586f0dfddb7a3a83fd164e800bcbc6fb089d6a247dfa444633f4663ae1e0bdf37b50a7a01f506e2220bbdd4b08c59fe60e455bdaeda7e5a0cdb2e6dfca66381a72962fa8a6f9847a87135ccf02a40da5b3b8e91e6e1f31542f85f90bce1de05188fe57355329031c66b3fde18bbdcbd2cbec42ea1d0fc803abed2f15c41d2f122674ea91b7280e818acb7549fe63135d2109b4014ec6002745301bd0ac59ca8e4f8d2fb699347b74e17818e3a57fa69c759312dcfde155b2a558a2385c8adab8a6d57f0f497eaf0833e3d930e83fed88c91e18a74c4f5ff45925a2bbdda22f9a4f1196",
        msg: "7e8c2d8a65f539210c047422ae57549195a08393",
        ct: "3816169fbfd376797be9b484032128b70d90ad2b",
        tag: "e974fd3e323c9500b1ed71327ea36d17",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 32,
        flags: "Pseudorandom",
        comment: "",
        key: "6f8307bb3d83d67866c2fa5b26f9cade",
        iv: "dfe93ed879e4b391ebbbfd37",
        aad: "1d72720dbbc40333e819a4def81f7bae137d8e52dc010ed901a390bf8c0ab6b435b08ef0184888bc83b14b98b59f6c56afd46131c5627b9e2a44f0a12a9a5356d9090c8b19c94f3f8651d49c74276bd9ae1071cad5f5040fbe1e99124ef44f3f813b13dff958e7331b949193bdf558fd14032c54f0e0ae7ac4d2e6a99d82a5da41135f0543ad377d217152497cf86435d24ee0c75997e3863133d322017aec98050b2fbc1dd8542293ae706889e754daf6ff8c91fb6533c5db7375dd3e365e6a18c546fa9463dfdb21d51c9cf23c9284a63cbfad197f376601101cb2f8a67b6e866569218043cd1745d25ecddf609ce2f9a8f76fb883780a393ea18b7624376b",
        msg: "81ebf69754857be5ad7ddf0062f866421089d136",
        ct: "e0350ae492e8ffbe275abf7ba45637bdb14c50c3",
        tag: "9986065d8421b32e95e14a41f0166474",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 33,
        flags: "Pseudorandom",
        comment: "",
        key: "3076741408f734ce25d48f982e8b844b",
        iv: "a2712eac5e06d3cc2864aa8b",
        aad: "18526e4efd995a0bf6405d9f906725c290278958d49554974d8fe025e7860daa225c1285b0573916a4b6741f7cc2e29ce4e525e12f436cb7ce0ad47df3d0f5bd80fb27e47635a4985fdaedf0e821f1c8959985cac49c97a4a02438d92b4afd4c855dcc7ef41ecfc36866334fcc05b2bb93ef13f00c5ea9b921e8a519d77f648e0efe9b5a62305a2ecf7d4999663a6ddfca517f1f36f0899b0bdef9f433c4bb2663c0cc1bb616e7d1949e522bec85485d371d1134c90eede75e865dc7be405b54c33f0acbace6cf780c78035b8035b6ea3f562a8d30a156c199fdafd25be06ee895581195ef125cb4e629e4f18e0bee979d31513896db8466e448e6b4600a316757",
        msg: "414ec6b149e54735302dada888b98b7fdb4c127c",
        ct: "683cb23d78c2d2add05e0740b25f0448ed1d84c3",
        tag: "d7b413997b6146d57a59e1bb57fcb0df",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 34,
        flags: "Pseudorandom",
        comment: "",
        key: "01842c51b9943da4ec4effc057f8c3e3",
        iv: "0d5bf8ade38ed384861839b8",
        aad: "e2b0c047ee9a7ebde0bc5c2a773f02703f2526226d7fd721a6bdae1d9701da986db6c9bf224f032947bbcc40b269e40c7a4fc1a3d667cf6379843ecc3b9d0664dcde0dfe8d803aa8e14a59cfea1cc58bd93e8a54d5936229a21c497bd75c4534e19480b2a50ae8de0b906f75c1dcf737b5179daf751c3d6f51a1111c4865139393ee95963393a8f98005546759565baf95be2334e57f7c23272c9eca778d9956ee16b187fe309d9e1e699c1a8acdf370fbcab37b1e107934bb156987a282bdef9f9a92758474d808a3e3b191a6476f3e6ed49dc08451e3404e65918fdba33ba8ea3ba09b5669b4be9a64b93bae5de662b8f35d4abbb68118de9d025ebeb599a9cd2b0e35fd82aa0df2d43b60a61512d5af934489302572f928b790e6aadff6b7304b1a4080cc4faf8c698daa3045c945d828d915da6dda0662545f7d85297a36438ea7315a48d9a097140776f3c43d28f522f8afa03000c5a0192b5fb776b3bd06d3d9c52c873fccb0ecd1a8e14187ae2621d2e2848ae30af7ed0758fdbbc497aa69d58441f4d4b8ea13aaac97c4bffc4d07dbc62ae27f00a8db0c5d1bb24042481369f6ccd4df85d9c58a90069897e17ae0334248e13306a936697d2b5dadde5ac6c10b554b6bbd27752101b5df1f1cbb8c0ec1977c4581ab8dcd26a31dff01433785206b6595e3b824b5834295407f5027159eee46189f390537ddce6db5",
        msg: "dfc40cf38738675120f03b12505589b2f02bba68",
        ct: "bd804d5e641bacf79266d1285affc151d8a95097",
        tag: "785093818a4e2f1b6e9d9ce9f00ea5bd",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 35,
        flags: "Pseudorandom",
        comment: "",
        key: "67bd1fe83e4500ddaea721035d4cf7e4",
        iv: "5449b293c849be9941b1fb3e",
        aad: "18b8e9b141288ca891606a88987057fa078efc47c0e270b36985c924506e4f8e4a3d1541d0535f515a370a3400e2408fc92d217f9f37fb0b972a3a7602cac98f8f0231a4d76cf584d9239ee816765cecd28f325b907e0b02b260609c70226a16ecd9bd67a64ea12c4b249c05a90112940200df3e70519a4b9ec136b6f535d4b8b2ae16c5a54cb8c57d87451697e5101e1d09a94d2117b30ce90c3685117e2194a379e7a5754da20179582f97767e633d141185fe3784a44d94210b214768aa51117ed5c880613623e4aabbb647721764a513425b8d90d4189651f1529e688466d8abed49e2a5f0f4493b878d4169848547f591277631f1fed6c97d167f8baa68920a2b0220d2ad5ae65cd09dcbbfab42bc666867378e40fd3ced9719a76659ba22213a5a23e30aeeef995164883299e7dd6fff1617b4287c3197cb3b1abd54b2f0ca573b1a4677a054f1232cd19803633fe57b041c768df7c3506313e7eaa365624833becd768fcc4a31ade932e71ade8ccbf400b3aa2d32891a4a173fb7498c9564c89b70548fd495ac2ea85c4bedb4c9136d1a0a6c1618c4f1aa8e619fef765e1c7410f86cd8ae7d0b7ed28947433cd0ff64f5f9029816d61080237f099aad2f8520f25d7685cc1893b3e8da3aafdb38846b6758ee02b5c5ac899b2c0738453be2a83b879f97cbad8e214786fb2a836c74e06ef190022f4b5557694c254bc7",
        msg: "c259151909cc0480abbae3f7fb6beac92258d37d",
        ct: "825fbfb294215daac805b77dff049a2bd469b8ce",
        tag: "686ad7f3001dd05b58e76ed3273dd29a",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 36,
        flags: "Pseudorandom",
        comment: "",
        key: "e7e0827a582b946828cb6df0d1c4617e",
        iv: "3a403192064a51df71a3554f",
        aad: "053d3468b4d0a5a6a12dff017c40218c2f990158c50a95503130bb92a5d7615973ec8827043b29222e15713fb9a58db90a397d31b16e21b3befd3d66d8990312b3f7ada3f39abbe92e17a1a66d6a290534b3110287915b08f47431a1bfb9c823e54a16b287a57d4c3463c838c462dc7898a3d7f5f653a945744dbb126bd21802e4684ad7dc90391b8b8000343db337145bf17fe31fdc434163ee6ae44ada02de6192bda57018dde5ba1f59721b4583968efe8613816c3502ac1b1ef162d0085f8df37b3436d14cc54684e898fcb695f15a59d7df60eaa028388d7fdca2bbd90e07a1a02281dc85e00d83750bef47fe0256b23ccd83c864e8619b7b7e75c9b24814e6533c4f7855e4fa21de0747c64795aac015ab532d033e205898a7511da32f898daed383a48314db35f75e7bf12c7a99e50eb8dc93f8700624438211cda86423cfde8d183ae5d6ad70133753e40f73652dfd03074fee034ce6d16ccfc0b3341a9ec18e630872f625e04129173313ee22b1cbcbd90ee74c5019173eed3ab2a47f16c8672e449e06e3bec4d05971fe8eba752d5d962e6e7d27408464441b3db18804fc1e5c428e970688d8c55f2980f30a6b86034ad2f79a76ef44c8d816345a6270c15c79deebf3dcbc1a1a968d318b6cccc09ab755cbe0f6ff4c23710935a4ea5bcab51c307454fba56cef1308b7cf0738626964ae7d2b65ad54d52872699b96",
        msg: "65e0007f93225599dfc59107720c503c0158f3f4",
        ct: "a7f77fcd36df3634b843d95336f1a6642daa3244",
        tag: "1105b50e220a2971dc90731a01af2c54",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 37,
        flags: "SpecialCase",
        comment: "special case",
        key: "00112233445566778899aabbccddeeff",
        iv: "000000000000000000000000",
        aad: "",
        msg: "5d5078da12857e409e1f3ae19cfc8a3a",
        ct: "70b0c110177e873599d05676fcde10ed",
        tag: "ffffffffffffffffffffffffffffffff",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 38,
        flags: "SpecialCase",
        comment: "special case",
        key: "00112233445566778899aabbccddeeff",
        iv: "ffffffffffffffffffffffff",
        aad: "",
        msg: "f3937d8216ab17e05ffb8b490a001a1c",
        ct: "362c07b231c4525edc14db3319f19f19",
        tag: "00000000000000000000000000000000",
        result: WycheproofResult::Valid,
    },
    WycheproofVector {
        tc_id: 39,
        flags: "ModifiedTag",
        comment: "Flipped bit 0 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "517976811555a04bb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 40,
        flags: "ModifiedTag",
        comment: "Flipped bit 1 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "527976811555a04bb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 41,
        flags: "ModifiedTag",
        comment: "Flipped bit 7 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "d07976811555a04bb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 42,
        flags: "ModifiedTag",
        comment: "Flipped bit 8 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507876811555a04bb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 43,
        flags: "ModifiedTag",
        comment: "Flipped bit 31 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976011555a04bb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 44,
        flags: "ModifiedTag",
        comment: "Flipped bit 32 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811455a04bb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 45,
        flags: "ModifiedTag",
        comment: "Flipped bit 33 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811755a04bb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 46,
        flags: "ModifiedTag",
        comment: "Flipped bit 63 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a0cbb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 47,
        flags: "ModifiedTag",
        comment: "Flipped bit 64 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb30921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 48,
        flags: "ModifiedTag",
        comment: "Flipped bit 71 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04b320921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 49,
        flags: "ModifiedTag",
        comment: "Flipped bit 77 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb22921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 50,
        flags: "ModifiedTag",
        comment: "Flipped bit 80 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20920a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 51,
        flags: "ModifiedTag",
        comment: "Flipped bit 96 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20921a3d91edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 52,
        flags: "ModifiedTag",
        comment: "Flipped bit 97 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20921a3da1edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 53,
        flags: "ModifiedTag",
        comment: "Flipped bit 103 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20921a3581edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 54,
        flags: "ModifiedTag",
        comment: "Flipped bit 120 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20921a3d81edae5",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 55,
        flags: "ModifiedTag",
        comment: "Flipped bit 121 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20921a3d81edae6",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 56,
        flags: "ModifiedTag",
        comment: "Flipped bit 126 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20921a3d81edaa4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 57,
        flags: "ModifiedTag",
        comment: "Flipped bit 127 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a04bb20921a3d81eda64",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 58,
        flags: "ModifiedTag",
        comment: "Flipped bits 0 and 64 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "517976811555a04bb30921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 59,
        flags: "ModifiedTag",
        comment: "Flipped bits 31 and 63 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976011555a0cbb20921a3d81edae4",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 60,
        flags: "ModifiedTag",
        comment: "Flipped bits 63 and 127 in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "507976811555a0cbb20921a3d81eda64",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 61,
        flags: "ModifiedTag",
        comment: "all bits of tag flipped",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "af86897eeaaa5fb44df6de5c27e1251b",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 62,
        flags: "ModifiedTag",
        comment: "Tag changed to all zero",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "00000000000000000000000000000000",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 63,
        flags: "ModifiedTag",
        comment: "tag changed to all 1",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "ffffffffffffffffffffffffffffffff",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 64,
        flags: "ModifiedTag",
        comment: "msbs changed in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "d0f9f60195d520cb3289a123589e5a64",
        result: WycheproofResult::Invalid,
    },
    WycheproofVector {
        tc_id: 65,
        flags: "ModifiedTag",
        comment: "lsbs changed in tag",
        key: "000102030405060708090a0b0c0d0e0f",
        iv: "505152535455565758595a5b",
        aad: "",
        msg: "202122232425262728292a2b2c2d2e2f",
        ct: "2610dc674b46c13dd4e2406d0c0873c4",
        tag: "517877801454a14ab30820a2d91fdbe5",
        result: WycheproofResult::Invalid,
    },
];

/// Test all 65 12-byte-IV Wycheproof vectors against gm-crypto SM4-GCM.
///
/// For `Valid` vectors:
/// - `encrypt_gcm(msg, iv, aad)` must produce ciphertext+tag matching expected
/// - `decrypt_gcm(ct, iv, aad, tag)` must recover msg
///
/// For `Invalid` vectors (all `ModifiedTag` bit-flip variants):
/// - `decrypt_gcm(ct, iv, aad, tag)` must return `Err` (tag corruption
///   must be detected)
#[test]
fn wycheproof_sm4_gcm_kat() {
    let mut n_valid = 0;
    let mut n_invalid = 0;
    for v in VECTORS_12B_IV {
        let key = hex::decode(v.key).expect("hex key");
        let iv = hex::decode(v.iv).expect("hex iv");
        let aad = hex::decode(v.aad).expect("hex aad");
        let msg = hex::decode(v.msg).expect("hex msg");
        let ct_expected = hex::decode(v.ct).expect("hex ct");
        let tag_expected = hex::decode(v.tag).expect("hex tag");

        let cipher = match Sm4Cipher::new(&key) {
            Ok(c) => c,
            Err(e) => panic!(
                "tc_id={} ({} flag={}): Sm4Cipher::new failed: {}",
                v.tc_id, v.comment, v.flags, e
            ),
        };

        match v.result {
            WycheproofResult::Valid => {
                n_valid += 1;
                let (ct, tag) = cipher.encrypt_gcm(&msg, &iv, &aad).unwrap_or_else(|e| {
                    panic!(
                        "tc_id={} ({} flag={}): encrypt failed: {}",
                        v.tc_id, v.comment, v.flags, e
                    )
                });
                if ct != ct_expected {
                    panic!(
                        "tc_id={} ({} flag={}): ciphertext mismatch\n  got  ct: {}\n  want ct: {}",
                        v.tc_id,
                        v.comment,
                        v.flags,
                        hex::encode(&ct),
                        hex::encode(&ct_expected),
                    );
                }
                if tag != tag_expected {
                    panic!(
                        "tc_id={} ({} flag={}): tag mismatch\n  got  tag: {}\n  want tag: {}",
                        v.tc_id,
                        v.comment,
                        v.flags,
                        hex::encode(&tag),
                        hex::encode(&tag_expected),
                    );
                }
                let decrypted = cipher
                    .decrypt_gcm(&ct_expected, &iv, &aad, &tag_expected)
                    .unwrap_or_else(|e| {
                        panic!(
                            "tc_id={} ({} flag={}): decrypt failed: {}",
                            v.tc_id, v.comment, v.flags, e
                        )
                    });
                if decrypted != msg {
                    panic!(
                        "tc_id={} ({} flag={}): decrypt round-trip mismatch",
                        v.tc_id, v.comment, v.flags,
                    );
                }
            }
            WycheproofResult::Invalid => {
                n_invalid += 1;
                let result = cipher.decrypt_gcm(&ct_expected, &iv, &aad, &tag_expected);
                if result.is_ok() {
                    panic!(
                        "tc_id={} ({} flag={}): decrypt SUCCEEDED but expected to fail",
                        v.tc_id, v.comment, v.flags,
                    );
                }
            }
        }
    }
    eprintln!(
        "wycheproof_sm4_gcm_kat: tested {n_valid} valid + {n_invalid} invalid vectors (of 65 12-byte-IV vectors in Wycheproof SM4-GCM)"
    );
}

/// Positive API-contract test: gm-crypto's `encrypt_gcm` must reject non-12B IVs.
///
/// This is the gm-crypto/src/sm4.rs length check, asserted via one sample per
/// non-supported IV-length class (0, 1, 8, 11, 13, 16, 32, 64, 128, 257). If a
/// future PR relaxes the 12-byte constraint, this test fails — the Wycheproof
/// 12B-IV test would still pass but the 39 non-12B vectors in the Wycheproof
/// suite would become runnable, requiring additional test logic.
#[test]
fn wycheproof_sm4_gcm_rejects_non_12b_iv() {
    let key = [0u8; 16];
    let cipher = Sm4Cipher::new(&key).unwrap();
    for iv_len in [0usize, 1, 8, 11, 13, 16, 32, 64, 128, 257] {
        let iv = vec![0u8; iv_len];
        assert!(
            cipher.encrypt_gcm(b"", &iv, b"").is_err(),
            "encrypt_gcm should reject {iv_len}-byte IV per API contract              (gm-crypto SM4_GCM_NONCE_LENGTH = 12)",
        );
    }
}
