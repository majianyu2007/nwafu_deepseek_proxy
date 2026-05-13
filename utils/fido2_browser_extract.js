/**
 * NWAFU CAS Passkey 信息提取器
 *
 * 在已登录 CAS 并绑定生物识别的浏览器中，打开 CAS 登录页后，
 * 在 F12 → Console 中粘贴运行此脚本。
 *
 * 会输出：
 *   1. localStorage 中的设备绑定信息（anonbiometricsd / anonbiometricsu / anonbiometricso）
 *   2. 一份 JSON 模板，保存为 .data/fido2_credential.json
 *
 * 使用方法：复制此文件全部内容，在浏览器 Console 中粘贴回车。
 */
(function () {
  'use strict';

  var anonbiometricsd = localStorage.getItem('anonbiometricsd');
  var anonbiometricsu = localStorage.getItem('anonbiometricsu');
  var anonbiometricso = localStorage.getItem('anonbiometricso');

  console.log('========== FIDO2 设备绑定信息 ==========');
  console.log('anonbiometricsd (设备绑定ID):', anonbiometricsd || '(未绑定！请先在个人中心开启生物识别)');
  console.log('anonbiometricsu (用户ID):     ', anonbiometricsu || '(无)');
  console.log('anonbiometricso (开关状态):   ', anonbiometricso || '(无)');
  console.log('');

  if (!anonbiometricsd) {
    console.log('⚠️  尚未绑定设备，请先完成以下步骤：');
    console.log('  1. 正常登录 CAS（密码 + TOTP）');
    console.log('  2. 进入 个人中心 → 账号安全 → 生物识别');
    console.log('  3. 按照页面指引绑定当前设备');
    console.log('  4. 回到登录页重新运行此脚本');
    return;
  }

  console.log('========== 配置文件模板（.data/fido2_credential.json） ==========');
  console.log('将下方 JSON 保存到 .data/fido2_credential.json，');
  console.log('并与 Bitwarden 导出的 keyValue 合并：');
  console.log('');
  console.log('  python utils/extract_fido2.py bitwarden_export.json --name NWAFU --save');
  console.log('');

  var template = {
    credentialId: '（从 Bitwarden 导出获取）',
    keyType: 'public-key',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: '（从 Bitwarden 导出获取，extract_fido2.py 自动填充）',
    rpId: 'authserver.nwafu.edu.cn',
    userHandle: anonbiometricsd ? '(unknown)' : '',
    userName: anonbiometricsu || '',
    deviceBindingId: anonbiometricsd || '',
    userDisplayName: anonbiometricsu || '',
    discoverable: 'false',
  };

  console.log(JSON.stringify(template, null, 2));

  console.log('');
  console.log('========== 后续步骤 ==========');
  console.log('1. 从 Bitwarden 导出（未加密 JSON）');
  console.log('2. 运行: python utils/extract_fido2.py bitwarden_export.json --name NWAFU --save');
  console.log('3. 编辑 .data/fido2_credential.json，添加 "deviceBindingId": "' + (anonbiometricsd || 'xxx') + '"');
  console.log('4. 重启代理');
})();
