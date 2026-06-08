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
