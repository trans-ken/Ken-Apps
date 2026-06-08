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
  if (!/^[1-9]{4}$/.test(String(pin))) {
    throw new Error('PINは1〜9の数字を4つで設定してください');
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
