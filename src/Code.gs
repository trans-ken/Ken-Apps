/**
 * TRANPASS - サーバーサイド（認証・データCRUD）
 *
 * - Webアプリのアクセスは「自分のみ」を想定（appsscript.json: access=MYSELF）
 * - 4桁PIN（1〜9）はハッシュ化して保管。失敗が続くと一定時間ロック
 * - Vault は暗号化して Google Drive 上の単一ファイルに保存
 */

var PROP = PropertiesService.getScriptProperties();

var FOLDER_NAME = 'TRANPASS';
var FILE_NAME = 'tranpass.enc';
var TOKEN_TTL = 1800;   // 認証トークン有効秒（30分）
var MAX_FAIL = 5;       // ロックまでの連続失敗回数
var LOCK_SECONDS = 300; // ロック時間（5分）

// ============================================================
//  エントリーポイント
// ============================================================
function doGet() {
  return HtmlService.createTemplateFromFile('Index')
    .evaluate()
    .setTitle('TRANPASS')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1, maximum-scale=1');
}

function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

// ============================================================
//  認証
// ============================================================
function getLoginState() {
  var pinSet = !!PROP.getProperty('PIN_HASH');
  var lockUntil = Number(PROP.getProperty('LOCK_UNTIL') || 0);
  var now = Date.now();
  var locked = lockUntil > now;
  return {
    pinSet: pinSet,
    locked: locked,
    lockRemaining: locked ? Math.ceil((lockUntil - now) / 1000) : 0
  };
}

/** 初回PIN設定（未設定時のみ） */
function setupPin(pin) {
  if (PROP.getProperty('PIN_HASH')) throw new Error('PINは既に設定されています');
  validatePinFormat(pin);
  var salt = randomBytesB64(16);
  PROP.setProperty('PIN_SALT', salt);
  PROP.setProperty('PIN_HASH', hashPin(pin, salt));
  getMasterKey(); // マスターキー初期化
  saveVaultData({ categories: defaultCategories(), entries: [] });
  return { token: issueToken() };
}

/** PIN検証 */
function verifyPin(pin) {
  var state = getLoginState();
  if (state.locked) throw new Error('ロック中です。約' + state.lockRemaining + '秒後に再試行してください');
  if (!state.pinSet) throw new Error('PINが未設定です');

  var salt = PROP.getProperty('PIN_SALT');
  if (hashPin(pin, salt) === PROP.getProperty('PIN_HASH')) {
    PROP.deleteProperty('FAIL_COUNT');
    PROP.deleteProperty('LOCK_UNTIL');
    return { token: issueToken() };
  }

  var fc = Number(PROP.getProperty('FAIL_COUNT') || 0) + 1;
  if (fc >= MAX_FAIL) {
    PROP.setProperty('LOCK_UNTIL', String(Date.now() + LOCK_SECONDS * 1000));
    PROP.deleteProperty('FAIL_COUNT');
    throw new Error('失敗が続いたため' + (LOCK_SECONDS / 60) + '分間ロックしました');
  }
  PROP.setProperty('FAIL_COUNT', String(fc));
  throw new Error('PINが違います（あと' + (MAX_FAIL - fc) + '回）');
}

function issueToken() {
  var token = randomBytesB64(24);
  CacheService.getUserCache().put('AUTH', token, TOKEN_TTL);
  return token;
}

function requireAuth(token) {
  var cur = CacheService.getUserCache().get('AUTH');
  if (!cur || !token || cur !== token) {
    throw new Error('セッションが切れました。再度ログインしてください');
  }
  CacheService.getUserCache().put('AUTH', cur, TOKEN_TTL); // TTL更新
}

function validatePinFormat(pin) {
  if (!/^[0-9]{4}$/.test(String(pin))) {
    throw new Error('PINは0〜9の数字を4つで設定してください');
  }
}

/** PINハッシュ（ソルト＋ストレッチング） */
function hashPin(pin, salt) {
  var h = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, salt + ':' + pin, Utilities.Charset.UTF_8);
  for (var i = 0; i < 2000; i++) {
    h = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, h);
  }
  return Utilities.base64Encode(h);
}

// ============================================================
//  マスターキー
// ============================================================
function getMasterKey() {
  var k = PROP.getProperty('MASTER_KEY');
  if (!k) {
    k = randomBytesB64(32);
    PROP.setProperty('MASTER_KEY', k);
  }
  return toUnsigned(Utilities.base64Decode(k));
}

// ============================================================
//  Drive 上の Vault ファイル
// ============================================================
function getFolder() {
  var id = PROP.getProperty('FOLDER_ID');
  if (id) {
    try { return DriveApp.getFolderById(id); } catch (e) {}
  }
  var it = DriveApp.getFoldersByName(FOLDER_NAME);
  var folder = it.hasNext() ? it.next() : DriveApp.createFolder(FOLDER_NAME);
  PROP.setProperty('FOLDER_ID', folder.getId());
  return folder;
}

function getVaultFile() {
  var id = PROP.getProperty('FILE_ID');
  if (id) {
    try { return DriveApp.getFileById(id); } catch (e) {}
  }
  var folder = getFolder();
  var it = folder.getFilesByName(FILE_NAME);
  var file = it.hasNext() ? it.next() : folder.createFile(FILE_NAME, '', 'text/plain');
  PROP.setProperty('FILE_ID', file.getId());
  return file;
}

function loadVaultData() {
  var content = getVaultFile().getBlob().getDataAsString('UTF-8');
  if (!content) return { categories: defaultCategories(), entries: [] };
  var data = JSON.parse(decryptString(content));
  if (!data.categories) data.categories = defaultCategories();
  if (!data.entries) data.entries = [];
  return data;
}

function saveVaultData(data) {
  getVaultFile().setContent(encryptString(JSON.stringify(data)));
}

function defaultCategories() {
  return ['銀行', '証券', 'クレジットカード', 'SNS', 'メール', 'ショッピング', 'その他'];
}

// ============================================================
//  データ API（すべてトークン必須）
// ============================================================
function apiLoad(token) {
  requireAuth(token);
  return loadVaultData();
}

function apiSaveEntry(token, entry) {
  requireAuth(token);
  var data = loadVaultData();
  var now = new Date().toISOString();
  if (!entry.id) {
    entry.id = Utilities.getUuid();
    entry.createdAt = now;
    entry.updatedAt = now;
    data.entries.push(entry);
  } else {
    entry.updatedAt = now;
    var found = false;
    for (var i = 0; i < data.entries.length; i++) {
      if (data.entries[i].id === entry.id) {
        entry.createdAt = data.entries[i].createdAt || now;
        data.entries[i] = entry;
        found = true;
        break;
      }
    }
    if (!found) { entry.createdAt = now; data.entries.push(entry); }
  }
  saveVaultData(data);
  return data;
}

function apiDeleteEntry(token, id) {
  requireAuth(token);
  var data = loadVaultData();
  data.entries = data.entries.filter(function(e) { return e.id !== id; });
  saveVaultData(data);
  return data;
}

function apiSaveCategories(token, categories) {
  requireAuth(token);
  var clean = [];
  (categories || []).forEach(function(c) {
    c = String(c).trim();
    if (c && clean.indexOf(c) === -1) clean.push(c);
  });
  var data = loadVaultData();
  data.categories = clean.length ? clean : defaultCategories();
  saveVaultData(data);
  return data;
}

function apiChangePin(token, oldPin, newPin) {
  requireAuth(token);
  var salt = PROP.getProperty('PIN_SALT');
  if (hashPin(oldPin, salt) !== PROP.getProperty('PIN_HASH')) {
    throw new Error('現在のPINが違います');
  }
  validatePinFormat(newPin);
  var newSalt = randomBytesB64(16);
  PROP.setProperty('PIN_SALT', newSalt);
  PROP.setProperty('PIN_HASH', hashPin(newPin, newSalt));
  return { ok: true };
}

/** 暗号化済みVaultのバックアップコピーをDriveに作成 */
function apiBackup(token) {
  requireAuth(token);
  var content = getVaultFile().getBlob().getDataAsString('UTF-8');
  var name = 'tranpass-backup-' +
    Utilities.formatDate(new Date(), Session.getScriptTimeZone(), 'yyyyMMdd-HHmmss') + '.enc';
  getFolder().createFile(name, content, 'text/plain');
  return { name: name };
}


/**
 * TRANPASS - 暗号化モジュール
 *
 * AES-256-CTR（純JS実装）＋ HMAC-SHA256（GASネイティブ）による
 * Encrypt-then-MAC 方式でVaultを暗号化します。
 *
 * 保存フォーマット（base64）:
 *   IV(16) || ciphertext(n) || HMAC-SHA256(32)
 *   HMAC は (IV || ciphertext) に対して macKey で計算
 *
 * encKey  = マスターキー（Script Properties に32バイトbase64で保管）
 * macKey  = SHA-256(masterKey || "TRANPASS-MAC")
 */

// ============================================================
//  AES ブロック暗号（Chris Veness 実装ベース / forward cipher）
// ============================================================
var Aes = {};

Aes.sBox = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
];

Aes.rCon = [
  [0x00,0x00,0x00,0x00],
  [0x01,0x00,0x00,0x00],
  [0x02,0x00,0x00,0x00],
  [0x04,0x00,0x00,0x00],
  [0x08,0x00,0x00,0x00],
  [0x10,0x00,0x00,0x00],
  [0x20,0x00,0x00,0x00],
  [0x40,0x00,0x00,0x00],
  [0x80,0x00,0x00,0x00],
  [0x1b,0x00,0x00,0x00],
  [0x36,0x00,0x00,0x00]
];

/** 16バイトブロックを暗号化（鍵スケジュール w を使用） */
Aes.cipher = function(input, w) {
  var Nb = 4;
  var Nr = w.length / Nb - 1;
  var state = [[],[],[],[]];
  for (var i = 0; i < 4 * Nb; i++) state[i % 4][Math.floor(i / 4)] = input[i];

  state = Aes.addRoundKey(state, w, 0, Nb);
  for (var round = 1; round < Nr; round++) {
    state = Aes.subBytes(state, Nb);
    state = Aes.shiftRows(state, Nb);
    state = Aes.mixColumns(state, Nb);
    state = Aes.addRoundKey(state, w, round, Nb);
  }
  state = Aes.subBytes(state, Nb);
  state = Aes.shiftRows(state, Nb);
  state = Aes.addRoundKey(state, w, Nr, Nb);

  var output = new Array(4 * Nb);
  for (var i = 0; i < 4 * Nb; i++) output[i] = state[i % 4][Math.floor(i / 4)];
  return output;
};

/** 鍵スケジュール生成（AES-256 は key=32バイト） */
Aes.keyExpansion = function(key) {
  var Nb = 4;
  var Nk = key.length / 4;
  var Nr = Nk + 6;
  var w = new Array(Nb * (Nr + 1));
  var temp = new Array(4);

  for (var i = 0; i < Nk; i++) {
    w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
  }
  for (var i = Nk; i < Nb * (Nr + 1); i++) {
    w[i] = new Array(4);
    for (var t = 0; t < 4; t++) temp[t] = w[i - 1][t];
    if (i % Nk === 0) {
      temp = Aes.subWord(Aes.rotWord(temp));
      for (var t = 0; t < 4; t++) temp[t] ^= Aes.rCon[i / Nk][t];
    } else if (Nk > 6 && i % Nk === 4) {
      temp = Aes.subWord(temp);
    }
    for (var t = 0; t < 4; t++) w[i][t] = w[i - Nk][t] ^ temp[t];
  }
  return w;
};

Aes.subBytes = function(s, Nb) {
  for (var r = 0; r < 4; r++)
    for (var c = 0; c < Nb; c++) s[r][c] = Aes.sBox[s[r][c]];
  return s;
};

Aes.shiftRows = function(s, Nb) {
  var t = new Array(4);
  for (var r = 1; r < 4; r++) {
    for (var c = 0; c < 4; c++) t[c] = s[r][(c + r) % Nb];
    for (var c = 0; c < 4; c++) s[r][c] = t[c];
  }
  return s;
};

Aes.mixColumns = function(s, Nb) {
  for (var c = 0; c < 4; c++) {
    var a = new Array(4);
    var b = new Array(4);
    for (var i = 0; i < 4; i++) {
      a[i] = s[i][c];
      b[i] = s[i][c] & 0x80 ? (s[i][c] << 1) ^ 0x011b : s[i][c] << 1;
    }
    s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
    s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
    s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
    s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
  }
  return s;
};

Aes.addRoundKey = function(state, w, rnd, Nb) {
  for (var r = 0; r < 4; r++)
    for (var c = 0; c < Nb; c++) state[r][c] ^= w[rnd * 4 + c][r];
  return state;
};

Aes.subWord = function(w) {
  for (var i = 0; i < 4; i++) w[i] = Aes.sBox[w[i]];
  return w;
};

Aes.rotWord = function(w) {
  var tmp = w[0];
  for (var i = 0; i < 3; i++) w[i] = w[i + 1];
  w[3] = tmp;
  return w;
};

/**
 * AES-256-CTR（暗号化・復号 共通）
 * @param {number[]} dataBytes 0-255 のバイト配列
 * @param {number[]} keyBytes  32バイト
 * @param {number[]} ivBytes   16バイト（初期カウンタ）
 * @return {number[]}
 */
function aesCtrCrypt(dataBytes, keyBytes, ivBytes) {
  var w = Aes.keyExpansion(keyBytes);
  var counter = ivBytes.slice(0);
  var out = new Array(dataBytes.length);
  var blocks = Math.ceil(dataBytes.length / 16);
  for (var b = 0; b < blocks; b++) {
    var keystream = Aes.cipher(counter, w);
    var start = b * 16;
    var end = Math.min(start + 16, dataBytes.length);
    for (var i = start; i < end; i++) out[i] = dataBytes[i] ^ keystream[i - start];
    // カウンタをビッグエンディアンで +1
    for (var j = 15; j >= 0; j--) {
      counter[j] = (counter[j] + 1) & 0xff;
      if (counter[j] !== 0) break;
    }
  }
  return out;
}

// ============================================================
//  高レベル 暗号化 / 復号
// ============================================================
function encryptString(plain) {
  var key = getMasterKey();
  var macKey = deriveMacKey(key);
  var iv = randomBytes(16);
  var ct = aesCtrCrypt(strToBytes(plain), key, iv);
  var signed = iv.concat(ct);
  var mac = toUnsigned(Utilities.computeHmacSha256Signature(toSignedBytes(signed), toSignedBytes(macKey)));
  return Utilities.base64Encode(toSignedBytes(signed.concat(mac)));
}

function decryptString(b64) {
  var key = getMasterKey();
  var macKey = deriveMacKey(key);
  var packed = toUnsigned(Utilities.base64Decode(b64));
  if (packed.length < 16 + 32) throw new Error('暗号データが壊れています');
  var iv = packed.slice(0, 16);
  var mac = packed.slice(packed.length - 32);
  var ct = packed.slice(16, packed.length - 32);
  var expected = toUnsigned(Utilities.computeHmacSha256Signature(
    toSignedBytes(iv.concat(ct)), toSignedBytes(macKey)));
  if (!constantTimeEqual(mac, expected)) throw new Error('データの整合性チェックに失敗しました');
  return bytesToStr(aesCtrCrypt(ct, key, iv));
}

function deriveMacKey(key) {
  return toUnsigned(Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, toSignedBytes(key.concat(strToBytes('TRANPASS-MAC')))));
}

// ============================================================
//  バイト操作ユーティリティ
// ============================================================
function toUnsigned(bytes) {
  var out = new Array(bytes.length);
  for (var i = 0; i < bytes.length; i++) out[i] = bytes[i] & 0xff;
  return out;
}

function toSignedBytes(bytes) {
  var out = new Array(bytes.length);
  for (var i = 0; i < bytes.length; i++) out[i] = bytes[i] > 127 ? bytes[i] - 256 : bytes[i];
  return out;
}

function strToBytes(str) {
  return toUnsigned(Utilities.newBlob(str).getBytes());
}

function bytesToStr(bytes) {
  return Utilities.newBlob(toSignedBytes(bytes)).getDataAsString('UTF-8');
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  var r = 0;
  for (var i = 0; i < a.length; i++) r |= a[i] ^ b[i];
  return r === 0;
}

/** UUID由来のエントロピーから n バイトの乱数を生成 */
function randomBytes(n) {
  var seed = Utilities.getUuid() + Utilities.getUuid() + Date.now() + ':' + Math.random();
  var out = [];
  var counter = 0;
  while (out.length < n) {
    var block = toUnsigned(Utilities.computeDigest(
      Utilities.DigestAlgorithm.SHA_256, seed + ':' + counter, Utilities.Charset.UTF_8));
    out = out.concat(block);
    counter++;
  }
  return out.slice(0, n);
}

function randomBytesB64(n) {
  return Utilities.base64Encode(toSignedBytes(randomBytes(n)));
}


/**
 * TRANPASS - 動作確認用テスト
 * GASエディタで runSelfTest を実行し、ログがすべて [OK] になることを確認してください。
 */
function runSelfTest() {
  testAesKnownAnswer_();
  testCtrRoundTrip_();
  testEncryptDecryptRoundTrip_();
  Logger.log('=== すべてのテストが完了しました ===');
}

/** FIPS-197 AES-256 既知応答テスト（ECB 1ブロック） */
function testAesKnownAnswer_() {
  var key = [];
  for (var i = 0; i < 32; i++) key.push(i); // 000102...1f
  var pt = [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
  var expected = '8ea2b7ca516745bfeafc49904b496089';
  var ct = Aes.cipher(pt, Aes.keyExpansion(key));
  var hex = ct.map(function(b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');
  Logger.log((hex === expected ? '[OK] ' : '[NG] ') + 'AES-256 KAT: ' + hex);
  if (hex !== expected) throw new Error('AES KAT 失敗');
}

/** CTRモードの暗号化→復号 ラウンドトリップ */
function testCtrRoundTrip_() {
  var key = randomBytes(32);
  var iv = randomBytes(16);
  var msg = strToBytes('Hello TRANPASS 日本語テスト 0123456789 #漢字');
  var ct = aesCtrCrypt(msg, key, iv);
  var dt = aesCtrCrypt(ct, key, iv);
  var ok = bytesToStr(dt) === bytesToStr(msg);
  Logger.log((ok ? '[OK] ' : '[NG] ') + 'CTR round-trip');
  if (!ok) throw new Error('CTR round-trip 失敗');
}

/** encryptString → decryptString（HMAC込み）ラウンドトリップ */
function testEncryptDecryptRoundTrip_() {
  var sample = JSON.stringify({
    categories: ['銀行', '証券'],
    entries: [{ id: '1', name: '○○銀行', password: 'p@ssW0rd!', memo: 'メモ📝' }]
  });
  var enc = encryptString(sample);
  var dec = decryptString(enc);
  var ok = dec === sample;
  Logger.log((ok ? '[OK] ' : '[NG] ') + 'encrypt/decrypt round-trip');
  if (!ok) throw new Error('encrypt/decrypt round-trip 失敗');
}
