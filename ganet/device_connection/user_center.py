"""Loopback-only account and paired-device management page."""
from __future__ import annotations

import json
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import pairing as controller, network as env


_LOGIN_LOCK = threading.Lock()
_LOGIN_IN_PROGRESS = False
_LOGIN_URL = ""
_TEMPLATE_PATH = Path(__file__).with_name("pages") / "user_center.html"
_BASE_CSS = '''<style>
@font-face{font-family:'GA Azonix';src:url(data:font/woff2;base64,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) format('woff2');font-weight:400;font-style:normal;font-display:swap}
:root{color-scheme:light;--bg:#fff;--surface:#fff;--surface2:#ededf0;--surface3:#f2f2f4;--txt:#1d1d1f;--txt2:#6e6e73;--mut:#b8b8bd;--line:#e6e6ea;--acc:#1d1d1f;--onAcc:#fff;--err:#d70015;--md-sys-color-success:#2ba24e;--r-md:18px;--r-lg:22px;--r-xl:28px;--sp-2:8px;--sp-5:20px;--shadow:0 8px 30px rgba(0,0,0,.08)}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0a0a0a;--surface:#161616;--surface2:#262626;--surface3:#1f1f1f;--txt:#f5f5f7;--txt2:#a1a1a6;--mut:#48484a;--line:#2c2c2e;--acc:#f5f5f7;--onAcc:#1d1d1f;--err:#ff453a;--md-sys-color-success:#32d74b}}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--txt);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;-webkit-font-smoothing:antialiased}.gaLogo{width:30px;height:30px;border-radius:9px;display:inline-flex;align-items:center;justify-content:center;padding-top:4px;background:var(--txt);color:var(--bg);font-family:'GA Azonix',-apple-system,BlinkMacSystemFont,sans-serif;font-size:12.5px;font-weight:400;letter-spacing:.02em;line-height:1;box-shadow:0 1px 2px rgba(0,0,0,.08)}.gaWordmark{font-family:'GA Azonix',-apple-system,BlinkMacSystemFont,sans-serif;font-size:14px;font-weight:400;letter-spacing:.08em;line-height:1;text-transform:uppercase}.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-md);overflow:hidden}.row{display:flex;align-items:center;min-height:56px;padding:10px 16px;gap:12px;border-bottom:1px solid var(--line)}.row:last-child{border-bottom:0}.row .k{font-size:15.5px}.row .v{flex:1;text-align:right;color:var(--txt2);display:flex;justify-content:flex-end}.rowBtn{width:100%;border:0;background:transparent;color:inherit;text-align:left;cursor:pointer}.btnPrimary{border:0;border-radius:var(--r-md);padding:15px 18px;background:var(--acc);color:var(--onAcc);font-size:15px;font-weight:650;cursor:pointer}.hint{font-size:12.5px;color:var(--mut);margin:10px 4px 0}.secLbl{font-size:13px;color:var(--mut)}.userHero{display:flex;align-items:center;gap:14px;padding:16px}.userHeroAvatarBtn{border:0;background:none;padding:0}.userAvatar{width:54px;height:54px;border-radius:50%;display:grid;place-items:center;background:var(--surface2)}.userHeroText{min-width:0}.userHeroName{font-size:17px;font-weight:650}.userHeroSub{font-size:13px;color:var(--mut)}.ucSignedOut{max-width:420px;margin:22vh auto;padding:0 24px;text-align:center}.ucSignedOut .ucMark{font-size:26px;color:var(--mut)}.ucSignedOut h1{margin:14px 0 8px;font-size:21px}.ucSignedOut p{margin:0;color:var(--txt2);font-size:14px;line-height:1.6}.ucSignedOut .hint{margin-top:14px}
</style>'''


def _render_page(token: str) -> bytes:
    page = _TEMPLATE_PATH.read_text(encoding="utf-8")
    # The approved preview references Android's app.css. The desktop page carries all
    # user-center CSS inline, so remove that unavailable preview-only dependency.
    page = page.replace('<link rel="stylesheet" href="app.css">', _BASE_CSS)
    page = page.replace("GAnet 用户中心 · 桌面预览", "GAnet 用户中心")
    page = page.replace("GAnet 用户中心 · 本地预览", "GAnet 用户中心")
    page = page.replace('<main class="ucMain ucSignedOut" id="signedOut"><div class="ucMark">✦</div><h1>登录后使用用户中心</h1><p>登录后可管理账号、电脑、手机和设备访问权限。</p><button class="btnPrimary" style="width:100%" onclick="previewSignIn()">登录 / 注册</button></main>', "")
    page = page.replace('<button class="ucPreviewSwitch" onclick="toggleLoginState()">预览未登录状态</button>', "")
    start = page.index("<script>")
    end = page.index("</script>", start) + len("</script>")
    return (page[:start] + _SCRIPT.replace("__TOKEN__", token) + page[end:]).encode("utf-8")


def _open_message(url: str) -> str:
    """One phrasing for both entry points: signing in is part of the user center."""
    if not url:
        return "GAnet 用户中心正在启动，请稍后重新打开"
    return "GAnet 用户中心已启动，请在浏览器打开：\n  %s" % url


def _open_after_login(publish) -> None:
    global _LOGIN_IN_PROGRESS
    try:
        from . import auth as login
        # Never pop a browser: the address is handed back to the caller instead,
        # so a desktop and a remote server behave identically.
        ok, _ = login.login_web(auth_base=env.AUTH_BASE, open_browser=False,
                                    on_url=publish, on_success=_serve_user_center)
        if ok:
            login._notify_auth("login")
    finally:
        with _LOGIN_LOCK:
            _LOGIN_IN_PROGRESS = False


def _has_ganet_login(login) -> bool:
    token = login.get_token()
    identity = login.current_identity() if token else None
    return bool(token and identity and identity.get("valid")
                and (identity.get("base_url") or "").rstrip("/") == env.AUTH_BASE)


def open_user_center() -> str:
    """Open login first when needed, then continue into the approved user center."""
    from . import auth as login

    if not _has_ganet_login(login):
        global _LOGIN_IN_PROGRESS, _LOGIN_URL
        with _LOGIN_LOCK:
            if _LOGIN_IN_PROGRESS:
                return _open_message(_LOGIN_URL)
            _LOGIN_IN_PROGRESS = True
            _LOGIN_URL = ""
        ready = threading.Event()

        def publish(url: str) -> None:
            global _LOGIN_URL
            with _LOGIN_LOCK:
                _LOGIN_URL = url
            ready.set()

        threading.Thread(target=_open_after_login, args=(publish,), daemon=True).start()
        ready.wait(5)
        with _LOGIN_LOCK:
            url = _LOGIN_URL
        return _open_message(url)

    # Reopening the user center with an existing formal login must also resume its
    # GAnet lifecycle: the original login event may predate listener registration
    # or a prior setup request.
    login._notify_auth("login")
    return "GAnet 用户中心已启动，请在浏览器打开：\n  %s" % _serve_user_center()


def _serve_user_center() -> str:
    """Start the loopback user-center server and return its authorized address.

    Also used as the login page's follow-on target, so signing in continues straight
    into the user center instead of asking the user to reopen it.
    """
    token = secrets.token_urlsafe(24)

    class Handler(BaseHTTPRequestHandler):
        def _json(self, value, status=200):
            data = json.dumps(value, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            return self.headers.get("X-User-State") == token or query.get("state") == [token]

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == "/":
                # The page embeds the API credential in its JS, so it needs the
                # same gate as /api/*; the address handed to the user carries state.
                if not self._authorized():
                    return self._json({"error": "forbidden"}, 403)
                data = _render_page(token)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif path == "/api/state" and self._authorized():
                self._json(controller.get_user_center_state())
            elif path == "/api/environment" and self._authorized():
                report = controller.get_environment_report()
                from ..device_access import host_adapter
                host = host_adapter.inspect_binding()
                report["host_binding"] = host
                report.setdefault("checks", {})["host_binding"] = bool(host.get("ok"))
                if not host.get("ok"):
                    report["status"] = "need_repair"
                    report["hint"] = "设备访问环境需要修复"
                    for node in report.get("chain", []):
                        if node.get("key") == "access":
                            node.update(ok=False, level="error", detail="设备访问环境需要修复")
                            break
                self._json(report)
            elif path == "/api/pair/qr" and self._authorized():
                pairing_id = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("pairing", [None])[0]
                data = controller.pairing_qr_svg(pairing_id)
                if data is None:
                    return self._json({"error": "not found"}, 404)
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'none'; script-src 'none'")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            if not self._authorized():
                return self._json({"error": "forbidden"}, 403)
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/logout":
                return self._logout()
            actions = {"/api/pair": controller.create_pairing,
                       "/api/approve": controller.approve_pairing,
                       "/api/cancel": controller.cancel_pairing,
                       "/api/environment/ssh-probe": controller.probe_phone_ssh}
            action = actions.get(path)
            if not action:
                return self._json({"error": "not found"}, 404)
            try:
                self._json({"ok": True, "message": action()})
            except RuntimeError as exc:
                self._json({"ok": False, "error": str(exc)}, 409)

        def _logout(self):
            """Sign out from the local GAnet account surface."""
            from . import auth as login
            lifecycle = login._notify_auth("logout")
            cleared = login.clear_token()
            self._json({"ok": True, "message": ("已退出 GA 登录" if cleared else "本机无登录态")
                        + (("\n" + lifecycle) if lifecycle else "")})
            # This server was created for the now-ended session; its token must die
            # with it. Shut down off-thread so this response still completes.
            threading.Thread(target=self.server.shutdown, daemon=True).start()

        def do_DELETE(self):
            if not self._authorized():
                return self._json({"error": "forbidden"}, 403)
            path = urllib.parse.urlsplit(self.path).path
            prefix = "/api/devices/"
            if not path.startswith(prefix):
                return self._json({"error": "not found"}, 404)
            self._json({"ok": controller.remove_device(
                urllib.parse.unquote(path[len(prefix):]))})

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = "http://127.0.0.1:%d/?state=%s" % (server.server_port, urllib.parse.quote(token))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return url


_SCRIPT = r'''<script>
const token='__TOKEN__',$=id=>document.getElementById(id);
const pcIcon='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>';
const phoneIcon='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4"/></svg>';
let state={},currentDevice=null,pairingCountdown=null,pairSheetDismissed=true,pairRequestSeq=0,stateRequestSeq=0,pairingBusy=false,pairMutationPromise=null,pairingExpired=false,envBusy=false,sshProbeBusy=false,loggedOut=false;
async function api(path,opt={}){opt.headers={...(opt.headers||{}),'X-User-State':token,'Content-Type':'application/json'};const r=await fetch(path,opt),d=await r.json();if(!r.ok||d.ok===false)throw Error(d.error||'请求失败');return d}
function showView(name){document.querySelectorAll('.ucView').forEach(v=>v.classList.toggle('on',v.id==='view-'+name));document.querySelectorAll('.ucNavBtn').forEach(b=>b.classList.toggle('on',b.dataset.view===name))}
function text(sel,value){document.querySelectorAll(sel).forEach(x=>x.textContent=value)}
const envSteps=[
  {name:'基础环境',keys:['network_component','qr_component','screenshot_media'],errors:{network_component:'未找到 GAnet 网络组件',qr_component:'缺少二维码组件',screenshot_media:'缺少电脑截图组件'}},
  {name:'GAnet 控制面',keys:['ga_profile'],errors:{ga_profile:'未连接 GAnet 控制面'}},
  {name:'SSH 服务',keys:['ssh_service','ssh_listening','ssh_loopback','listening'],errors:{ssh_service:'GAnet 网络组件未运行',ssh_listening:'私有网络 SSH 监听未就绪',ssh_loopback:'本机回环 SSH 监听未就绪',listening:'本机 SSH 端口不可达'}},
  {name:'安全性检查',keys:['managed_keys','managed_keys_acl','host_key','host_binding'],errors:{managed_keys:'未创建 GAnet 授权文件',managed_keys_acl:'GAnet 授权文件权限需要修复',host_key:'内嵌 SSH 主机密钥未生成',host_binding:'设备访问环境需要修复'}},
  {name:'模拟手机请求',keys:['ssh_probe'],errors:{ssh_probe:'模拟手机 SSH 公钥认证未通过'}}
];
function renderEnvironment(environment){const checks=environment?.checks||{},chain=environment?.chain||[],details=Object.fromEntries(chain.map(node=>[node.key,node.detail])),levels=Object.fromEntries(chain.map(node=>[node.key,node.level]));const nodes=[...document.querySelectorAll('.ucEnvNode')],links=[...document.querySelectorAll('.ucEnvLink')];envSteps.forEach((step,index)=>{const node=nodes[index],chainKey=['base','network','ssh','access'][index],probe=step.keys[0]==='ssh_probe',unchecked=probe&&checks.ssh_probe===null,failed=unchecked?[]:step.keys.filter(key=>checks[key]!==true),warning=!probe&&!failed.length&&levels[chainKey]==='warning',detail=probe?(environment?.ssh_probe?.detail||'尚未验证'):details[chainKey];node.classList.remove('checking');node.classList.toggle('ok',!unchecked&&!failed.length&&!warning);node.classList.toggle('warn',warning);node.classList.toggle('fail',!unchecked&&failed.length);node.querySelector('b').textContent=step.name;node.querySelector('.ucEnvError').textContent=unchecked?'尚未验证':failed.length?(detail||failed.map(key=>step.errors[key]).join('；')):detail||'已就绪';if(index>0)links[index-1].classList.toggle('fail',(!unchecked&&failed.length)||nodes[index-1].classList.contains('fail'))})}
function setEnvironmentNotice(text,mode){const nodes=[...document.querySelectorAll('.ucEnvNode')];envSteps.forEach((step,index)=>{const node=nodes[index];node.classList.remove('ok');node.classList.toggle('checking',mode==='checking');node.classList.toggle('fail',mode==='fail');node.querySelector('b').textContent=step.name;node.querySelector('.ucEnvError').textContent=text});document.querySelectorAll('.ucEnvLink').forEach(link=>link.classList.toggle('fail',mode==='fail'))}
// 环境探测要调用网络组件，慢且可能卡住；与页面渲染完全解耦，节点自己显示进度。
async function refreshEnvironment(){if(envBusy)return;envBusy=true;const retry=document.getElementById('envRetry');if(retry)retry.disabled=true;setEnvironmentNotice('正在检查','checking');try{const environment=await api('/api/environment');const alert=document.querySelector('.ucMeshAlert');if(alert)alert.style.display=environment.status==='ok'?'none':'flex';renderEnvironment(environment)}catch(e){setEnvironmentNotice('检查未完成','fail')}finally{envBusy=false;if(retry)retry.disabled=false}}
async function runSshProbe(){if(sshProbeBusy)return;sshProbeBusy=true;const button=document.getElementById('sshProbe'),nodes=[...document.querySelectorAll('.ucEnvNode')],node=nodes[envSteps.length-1];if(button)button.disabled=true;if(node){node.classList.remove('ok','fail');node.classList.add('checking');node.querySelector('.ucEnvError').textContent='正在验证'}try{await api('/api/environment/ssh-probe',{method:'POST'});await refreshEnvironment()}catch(e){if(node){node.classList.remove('checking','ok');node.classList.add('fail');node.querySelector('.ucEnvError').textContent='验证未完成'}toastError(e)}finally{sshProbeBusy=false;if(button)button.disabled=false}}
function formatRemaining(expiresAt){const seconds=Math.max(0,Math.ceil((new Date(expiresAt).getTime()-Date.now())/1000));return `${String(Math.floor(seconds/60)).padStart(2,'0')}:${String(seconds%60).padStart(2,'0')}`}
function updatePairingTimer(){if(!state.pairing?.expires_at)return;const timer=document.querySelector('.ucTimer'),remaining=formatRemaining(state.pairing.expires_at);if(!timer)return;if(remaining==='00:00'){pairingExpired=true;document.querySelector('.ucCode').classList.add('expired');timer.className='ucTimer';timer.textContent='二维码已过期';document.getElementById('restartPair').disabled=false;document.getElementById('approvePair').hidden=true;clearInterval(pairingCountdown);pairingCountdown=null;return}if(state.pairing.state==='phone_verified')return;timer.className='ucTimer';timer.textContent=`有效期剩余 ${remaining} · 使用手机 GA 扫描二维码`}
function renderPairing(pairing){const claimed=pairing.state==='phone_verified',failed=pairing.state==='security_failed',expired=['expired','security_failed'].includes(pairing.state)||formatRemaining(pairing.expires_at)==='00:00',candidate=pairing.candidate||{},close=document.getElementById('closePair'),restart=document.getElementById('restartPair'),approve=document.getElementById('approvePair'),timer=document.querySelector('.ucTimer');approve.disabled=!claimed||expired||pairingBusy;document.querySelector('#pairSheet .ucDialogActions').classList.toggle('claimed',claimed);if(failed){timer.className='ucTimer';timer.textContent='安全验证失败，请重新生成二维码';restart.disabled=false;}if(claimed){timer.className='ucTimer ucPairBusy';timer.textContent='手机已验证，等待当前电脑确认';}document.getElementById('pairCodeView').style.display=claimed?'none':'block';document.getElementById('pairConfirmView').classList.toggle('on',claimed);close.textContent=claimed?'取消':'关闭';restart.hidden=claimed;if(claimed){document.getElementById('pairCandidateModel').textContent=candidate.model||'Android phone';document.querySelector('#pairSheet .ucDialogTop p').textContent='核对手机信息后，在当前电脑本地确认本次访问。'}else{document.querySelector('#pairSheet .ucDialogTop p').textContent='在手机 GA 中打开「设置 → GAnet」，扫描下面的短期二维码。'}}
function render(s){state=s;const i=s.identity||{};text('.ucProfile b',i.nickname||i.email||'GA 用户');text('.ucProfile span',i.email||'');text('.userHeroName',i.nickname||i.email||'GA 用户');text('.userHeroSub','已登录');const vals=document.querySelectorAll('.ucInfoRow .v');if(vals[0])vals[0].textContent=i.email||'—';if(vals[1])vals[1].textContent=i.userId||'—';if(vals[2])vals[2].textContent='已登录';if(vals[3])vals[3].textContent=i.exp?new Date(i.exp*1000).toLocaleDateString('zh-CN'):'—';const box=document.querySelector('.ucDevices');box.innerHTML=(s.devices||[]).length?s.devices.map(d=>`<button class="ucDevice" data-id="${esc(d.device_id)}"><span class="ucDeviceIcon">${phoneIcon}</span><span class="ucDeviceName"><b>${esc(d.display_name||d.model||'Android phone')}</b><span>${esc(d.model||'Android phone')} · ${d.authorized?'SSH 已授权':'授权已失效'}</span></span><svg class="ucDeviceChev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg></button>`).join(''):'<div class="ucDevice"><span class="ucDeviceName"><b>还没有已配对手机</b><span>点击“添加设备”开始配对</span></span></div>';box.querySelectorAll('[data-id]').forEach(b=>b.onclick=()=>openDevice(b.dataset.id));if(s.pairing){renderPairing(s.pairing);const code=document.querySelector('.ucCode'),qrSrc='/api/pair/qr?state='+encodeURIComponent(token)+'&pairing='+encodeURIComponent(s.pairing.pairing_id)+'&t='+pairRequestSeq,qrImg=code.querySelector('img');if(!qrImg||qrImg.getAttribute('src')!==qrSrc)code.innerHTML='<img alt="设备互联二维码" src="'+qrSrc+'">';code.classList.toggle('expired',['expired','security_failed'].includes(s.pairing.state)||formatRemaining(s.pairing.expires_at)==='00:00');const timer=document.querySelector('.ucTimer');timer.textContent='';pairingExpired=['expired','security_failed'].includes(s.pairing.state)||formatRemaining(s.pairing.expires_at)==='00:00';document.getElementById('approvePair').hidden=s.pairing.state!=='phone_verified'||pairingExpired;document.getElementById('restartPair').disabled=!pairingExpired;if(!pairSheetDismissed)document.getElementById('pairSheet').classList.add('on');if(pairingCountdown)clearInterval(pairingCountdown);if(s.pairing.state!=='phone_verified'){updatePairingTimer();pairingCountdown=setInterval(updatePairingTimer,1000)}}else{pairingExpired=false;document.getElementById('restartPair').disabled=true;if(pairingCountdown){clearInterval(pairingCountdown);pairingCountdown=null}}}
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function refresh(){const seq=++stateRequestSeq;try{const next=await api('/api/state');if(seq===stateRequestSeq)render(next)}catch(e){if(seq===stateRequestSeq)toastError(e)}finally{if(seq===stateRequestSeq)document.getElementById('pageLoading').hidden=true}}
function showPairError(error){const raw=error?.message||String(error||'二维码生成失败'),message=raw.includes('缺少二维码组件')?'缺少二维码组件，先对 GA 发送“帮我配置 GAnet”':raw;document.querySelector('.ucCode').innerHTML='<div class="ucPairError"><span class="ucPairErrorIcon" aria-hidden="true">!</span><span>'+esc(message)+'</span></div>';document.querySelector('.ucTimer').textContent='';document.getElementById('restartPair').disabled=false;document.getElementById('approvePair').hidden=true}
function showPairLoading(){pairingExpired=false;document.querySelector('.ucCode').classList.remove('expired');document.getElementById('pairCodeView').style.display='block';document.getElementById('pairConfirmView').classList.remove('on');document.querySelector('#pairSheet .ucDialogTop p').textContent='在手机 GA 中打开「设置 → GAnet」，扫描下面的短期二维码。';document.querySelector('.ucCode').innerHTML='<span class="ucCodeLoading" aria-label="正在生成"><i></i><i></i><i></i></span>';document.querySelector('.ucTimer').textContent='正在生成短期二维码…';document.querySelector('#pairSheet .ucDialogActions').classList.remove('claimed');document.getElementById('closePair').textContent='关闭';document.getElementById('restartPair').hidden=false;document.getElementById('restartPair').disabled=true;document.getElementById('approvePair').hidden=true}
async function openPair(){pairSheetDismissed=false;document.getElementById('pairSheet').classList.add('on');if(state.pairing){const expired=state.pairing.state==='expired'||formatRemaining(state.pairing.expires_at)==='00:00';if(expired){pairingExpired=true;return restartPair()}render(state);return}if(pairingBusy)return;pairingBusy=true;const seq=++pairRequestSeq;showPairLoading();try{if(pairMutationPromise)await pairMutationPromise;pairMutationPromise=api('/api/pair',{method:'POST'});await pairMutationPromise;if(seq===pairRequestSeq)await refresh()}catch(e){if(seq===pairRequestSeq){pairingExpired=true;showPairError(e)}}finally{pairMutationPromise=null;if(seq===pairRequestSeq)pairingBusy=false}}
async function restartPair(){if(pairingBusy||!pairingExpired)return;pairingBusy=true;const seq=++pairRequestSeq;pairSheetDismissed=false;showPairLoading();try{if(pairMutationPromise)await pairMutationPromise;if(state.pairing){pairMutationPromise=api('/api/cancel',{method:'POST'});await pairMutationPromise;state.pairing=null}pairMutationPromise=api('/api/pair',{method:'POST'});await pairMutationPromise;if(seq===pairRequestSeq)await refresh()}catch(e){if(seq===pairRequestSeq){pairingExpired=true;showPairError(e)}}finally{pairMutationPromise=null;if(seq===pairRequestSeq)pairingBusy=false}}
async function approvePair(){const approve=document.getElementById('approvePair'),timer=document.querySelector('.ucTimer');try{approve.disabled=true;timer.className='ucTimer ucPairBusy';timer.textContent='正在授权手机并同步结果';await api('/api/approve',{method:'POST'});closePair();await refresh()}catch(e){approve.disabled=false;timer.className='ucTimer';toastError(e)}}
async function closePair(){if(state.pairing?.state==='phone_verified'){if(pairMutationPromise)return;pairMutationPromise=api('/api/cancel',{method:'POST'});try{await pairMutationPromise;state.pairing=null}catch(e){toastError(e);return}finally{pairMutationPromise=null}}pairSheetDismissed=true;document.getElementById('pairSheet').classList.remove('on');if(pairingCountdown){clearInterval(pairingCountdown);pairingCountdown=null}}
function openSetupHelp(){document.getElementById('setupSheet').classList.add('on')}function closeSetupHelp(){document.getElementById('setupSheet').classList.remove('on')}
function openSetupFromPair(){closePair();openSetupHelp()}
async function copySetupPrompt(){const value='帮我配置 GAnet';try{await navigator.clipboard.writeText(value)}catch(e){const t=document.createElement('textarea');t.value=value;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove()}document.getElementById('copyHint').textContent='已复制，可以直接发送给 GA。'}
function openDevice(id){currentDevice=(state.devices||[]).find(d=>d.device_id===id);if(!currentDevice)return;document.getElementById('deviceDetail').innerHTML=`<div class="ucDetailHero"><span class="ucDetailIcon">${phoneIcon}</span><span class="ucDetailIdentity"><b>${esc(currentDevice.display_name||currentDevice.model||'Android phone')}</b><span>${esc(currentDevice.model||'Android phone')} · 已配对手机</span></span></div><section class="ucDetailSection"><h3 class="ucDetailLabel">设备信息</h3><div class="ucDetailCard"><div class="ucDetailLine"><b>设备类型</b><span>Android 手机</span></div><div class="ucDetailLine"><b>授权状态</b><span>${currentDevice.authorized?'已授权':'授权已失效'}</span></div></div></section>`;document.getElementById('removeDevice').hidden=false;document.getElementById('deviceSheet').classList.add('on')}
function closeDevice(){document.getElementById('deviceSheet').classList.remove('on')}
function openRemoveConfirm(){document.getElementById('removeName').textContent=currentDevice?.display_name||currentDevice?.model||'设备';document.getElementById('removeSheet').classList.add('on')}function closeRemoveConfirm(){document.getElementById('removeSheet').classList.remove('on')}
async function confirmRemove(){try{const removedId=currentDevice.device_id;await api('/api/devices/'+encodeURIComponent(removedId),{method:'DELETE'});state.devices=(state.devices||[]).filter(device=>device.device_id!==removedId);currentDevice=null;closeRemoveConfirm();closeDevice();render(state);refresh()}catch(e){toastError(e)}}
function toastError(e){window.alert(e.message||String(e))}
async function logout(){if(!window.confirm('确定退出 GA 登录？'))return;try{const r=await api('/api/logout',{method:'POST'});showSignedOut(r.message||'已退出 GA 登录')}catch(e){toastError(e)}}
function showSignedOut(message){loggedOut=true;if(pairingCountdown){clearInterval(pairingCountdown);pairingCountdown=null}document.body.innerHTML='<div class="ucSignedOut"><div class="ucMark">✦</div><h1>已退出登录</h1><p>'+esc(message).replace(/\n/g,'<br>')+'</p><p class="hint">重新打开 GAnet 用户中心即可登录</p></div>'}
document.querySelector('.ucLogoutRow').onclick=logout;document.getElementById('closePair').onclick=closePair;document.getElementById('restartPair').onclick=restartPair;document.getElementById('removeDevice').onclick=openRemoveConfirm;document.querySelector('#removeSheet .ucRemoveBtn').onclick=confirmRemove;
const pairActions=document.querySelector('#pairSheet .ucDialogActions');pairActions.insertAdjacentHTML('beforeend','<button class="btnPrimary" id="approvePair" hidden>确认配对</button>');document.getElementById('approvePair').onclick=approvePair;
setInterval(()=>{if(loggedOut)return;const sheet=document.getElementById('pairSheet');if(sheet&&sheet.classList.contains('on'))refresh()},2000);refresh();refreshEnvironment();
</script>'''
