export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const action = url.searchParams.get('action');
  const method = request.method;

  const cors = {
    'Access-Control-Allow-Origin': url.origin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
  };

  if (method === 'OPTIONS') return new Response(null, { headers: cors });

  try {
    let body = {};
    if (method === 'POST') {
      try { body = await request.json(); } catch { body = {}; }
    }

    const ctx = {
      request, env, url, body, method,
      ipHash: await sha256Hex(request.headers.get('CF-Connecting-IP') || ''),
      cookieRaw: getCookie(request, 'tdao_cookie') || body.cookie || '',
    };

    switch (action) {
      case 'posts':         return json(await getPosts(env), cors);
      case 'post':          return json(await createPost(ctx), cors);
      case 'reply':         return json(await createReply(ctx), cors);
      case 'claim_cookie':  return json(await claimCookie(ctx), cors);
      case 'verify_cookie': return json(await verifyCookie(ctx), cors);
      case 'me':            return json(await me(ctx), cors);
      case 'login':         return json(await login(ctx), cors);
      case 'logout':        return json(await logout(ctx), cors);
      case 'hide_post':
      case 'hide_reply':    return json(await hideItem(ctx, action), cors);
      case 'pin_post':      return json(await pinPost(ctx), cors);
      case 'ban':           return json(await banItem(ctx), cors);
      case 'delete_post':   return json(await deletePost(ctx), cors);
      case 'delete_reply':  return json(await deleteReply(ctx), cors);
      case 'get_staffs':    return json(await getStaffs(ctx), cors);
      case 'delete_staff':  return json(await deleteStaff(ctx), cors);
      default:              return json({ error: '未知 action' }, cors, 404);
    }
  } catch (e) {
    return json({ error: e.message || '服务器错误' }, cors, 500);
  }
}

function json(data, cors, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

function getCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  const m = raw.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function parseCookie(cookieStr) {
  const [id, secret] = String(cookieStr || '').split('#');
  return { id: id || '', secret: secret || '' };
}

async function getRole(env, cookieStr) {
  if (!cookieStr) return null;
  const { id, secret } = parseCookie(cookieStr);
  if (!id || !secret) return null;
  const row = await env.DB.prepare(
    'SELECT role, display FROM cookies WHERE id = ? AND secret = ? AND banned = 0 AND (expires_at IS NULL OR expires_at > ?)'
  ).bind(id, secret, Date.now()).first();
  return row || null;
}

async function requireStaff(env, cookieStr) {
  const r = await getRole(env, cookieStr);
  if (!r || !['super', 'admin', 'mod'].includes(r.role)) throw new Error('无权限');
  return r;
}

async function requireSuper(env, cookieStr) {
  const r = await getRole(env, cookieStr);
  if (!r || r.role !== 'super') throw new Error('仅超级管理员可操作');
  return r;
}

async function checkBan(env, ipHash, cookieStr) {
  const { id } = parseCookie(cookieStr);
  const now = Date.now();
  const ipBan = await env.DB.prepare(
    'SELECT 1 FROM bans WHERE type = ? AND val = ? AND (expires_at IS NULL OR expires_at > ?)'
  ).bind('ip', ipHash, now).first();
  if (ipBan) throw new Error('IP 已被封禁');
  if (id) {
    const cBan = await env.DB.prepare(
      'SELECT 1 FROM bans WHERE type = ? AND val = ? AND (expires_at IS NULL OR expires_at > ?)'
    ).bind('cookie', id, now).first();
    if (cBan) throw new Error('饼干已被封禁');
  }
}

async function bumpRate(env, bucket, window, limit) {
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (bucket, window, calls) VALUES (?, ?, 1)
     ON CONFLICT(bucket, window) DO UPDATE SET calls = calls + 1
     RETURNING calls`
  ).bind(bucket, window).first();
  if (!row || row.calls > limit) throw new Error('操作过于频繁，请稍后再试');
}

function utcDay() { return new Date().toISOString().slice(0, 10); }
function utcMinute() { return new Date().toISOString().slice(0, 16); }
function safeParse(s) { try { return JSON.parse(s); } catch { return []; } }

async function getPosts(env) {
  const { results: posts } = await env.DB.prepare(
    'SELECT * FROM posts ORDER BY is_pinned DESC, id DESC LIMIT 200'
  ).all();
  const ids = posts.map(p => p.id);
  let replies = [];
  if (ids.length) {
    const placeholders = ids.map(() => '?').join(',');
    const { results } = await env.DB.prepare(
      `SELECT * FROM replies WHERE post_id IN (${placeholders}) ORDER BY id ASC`
    ).bind(...ids).all();
    replies = results;
  }
  const replyMap = {};
  for (const r of replies) { (replyMap[r.post_id] ||= []).push(formatReply(r)); }
  return posts.map(p => formatPost(p, replyMap[p.id] || []));
}

function formatPost(p, replies) {
  return {
    id: p.id, global_id: p.global_id, title: p.title, content: p.content, author: p.author,
    images: safeParse(p.images), cookie: p.cookie_id, created_at: p.created_at,
    is_hidden: !!p.is_hidden, is_pinned: !!p.is_pinned, ip_hash: p.ip_hash, replies,
  };
}

function formatReply(r) {
  return {
    id: r.id, global_id: r.global_id, content: r.content, author: r.author,
    images: safeParse(r.images), cookie: r.cookie_id, created_at: r.created_at,
    is_hidden: !!r.is_hidden, ip_hash: r.ip_hash,
  };
}

async function createPost(ctx) {
  const { env, body, ipHash, cookieRaw } = ctx;
  await checkBan(env, ipHash, cookieRaw);
  const role = await getRole(env, cookieRaw);
  if (!role) throw new Error('饼干无效或已过期，请重新领取');
  await bumpRate(env, 'post:' + (parseCookie(cookieRaw).id || ipHash), utcMinute(), 4);

  const title = String(body.title || '').trim().slice(0, 50);
  const content = String(body.content || '').trim();
  const author = String(body.author || '').trim().slice(0, 50);
  const images = Array.isArray(body.images) ? body.images.filter(isSafeUrl).slice(0, 9) : [];

  if (!content) throw new Error('正文不能为空');
  const counter = await env.DB.prepare(`UPDATE counters SET value = value + 1 WHERE name = 'global_post_id' RETURNING value`).first();
  await env.DB.prepare(`INSERT INTO posts (global_id, title, content, author, images, cookie_id, ip_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(counter.value, title, content, author, JSON.stringify(images), parseCookie(cookieRaw).id, ipHash, Date.now()).run();
  return { ok: true, global_id: counter.value };
}

async function createReply(ctx) {
  const { env, body, url, ipHash, cookieRaw } = ctx;
  await checkBan(env, ipHash, cookieRaw);
  const role = await getRole(env, cookieRaw);
  if (!role) throw new Error('饼干无效或已过期，请重新领取');
  const postId = Number(url.searchParams.get('post_id') || body.post_id);
  if (!postId) throw new Error('缺少 post_id');
  await bumpRate(env, 'reply:' + (parseCookie(cookieRaw).id || ipHash), utcMinute(), 6);

  const content = String(body.content || '').trim();
  const author = String(body.author || '').trim().slice(0, 50);
  const images = Array.isArray(body.images) ? body.images.filter(isSafeUrl).slice(0, 9) : [];
  if (!content) throw new Error('回复正文不能为空');
  const counter = await env.DB.prepare(`UPDATE counters SET value = value + 1 WHERE name = 'global_post_id' RETURNING value`).first();
  await env.DB.prepare(`INSERT INTO replies (global_id, post_id, content, author, images, cookie_id, ip_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(counter.value, postId, content, author, JSON.stringify(images), parseCookie(cookieRaw).id, ipHash, Date.now()).run();
  return { ok: true };
}

async function claimCookie(ctx) {
  const { env, ipHash } = ctx;
  const staff = await getRole(env, ctx.cookieRaw);
  if (staff && ['super', 'admin', 'mod'].includes(staff.role)) throw new Error('管理账号不能领取饼干');
  const today = utcDay();
  const perIp = await env.DB.prepare(`INSERT INTO cookie_claims (day, ip_hash, calls) VALUES (?, ?, 1) ON CONFLICT(day, ip_hash) DO UPDATE SET calls = calls + 1 RETURNING calls`).bind(today, ipHash).first();
  if (perIp.calls > 1) throw new Error('今天已经领取过饼干，请 24 小时后再来');
  const globalRow = await env.DB.prepare(`INSERT INTO cookie_claims (day, ip_hash, calls) VALUES (?, '*', 1) ON CONFLICT(day, ip_hash) DO UPDATE SET calls = calls + 1 RETURNING calls`).bind(today).first();
  if (globalRow.calls > 50) throw new Error('今日饼干已发完，明天再来吧');
  const id = randomAlphaNum(8), secret = randomAlphaNum(32);
  await env.DB.prepare('INSERT INTO cookies (id, secret, role, created_at) VALUES (?, ?, ?, ?)').bind(id, secret, 'user', Date.now()).run();
  return { cookie: `${id}#${secret}` };
}

async function verifyCookie(ctx) {
  const { env, body } = ctx;
  const raw = String(body.cookie || '');
  const { id, secret } = parseCookie(raw);
  if (!id || !secret) throw new Error('格式不正确');
  const row = await env.DB.prepare('SELECT id FROM cookies WHERE id = ? AND secret = ? AND banned = 0 AND (expires_at IS NULL OR expires_at > ?)').bind(id, secret, Date.now()).first();
  if (!row) throw new Error('饼干无效、未发放或已过期');
  return { ok: true, id };
}

async function me(ctx) {
  const { env, cookieRaw } = ctx;
  const adminToken = getCookie(ctx.request, 'tdao_admin');
  if (adminToken) {
    const s = await env.DB.prepare('SELECT cookie_id FROM admin_sessions WHERE token = ? AND expires_at > ?').bind(adminToken, Date.now()).first();
    if (s) {
      const row = await env.DB.prepare('SELECT id, role, display FROM cookies WHERE id = ? AND banned = 0').bind(s.cookie_id).first();
      if (row) return { role: row.role, cookie: `${row.id}#${await secretOf(env, row.id)}`, display: row.display || '' };
    }
  }
  const role = await getRole(env, cookieRaw);
  if (!role) return { role: 'guest' };
  return { role: role.role, cookie: cookieRaw, display: role.display || '' };
}

async function secretOf(env, id) {
  const row = await env.DB.prepare('SELECT secret FROM cookies WHERE id = ?').bind(id).first();
  return row ? row.secret : '';
}

async function login(ctx) {
  const { env, body } = ctx;
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!username || !password) throw new Error('请输入账号密码');
  const row = await env.DB.prepare(`SELECT id, secret, role, display FROM cookies WHERE id = ? AND secret = ? AND role IN ('super','admin','mod') AND banned = 0`).bind(username, password).first();
  if (!row) throw new Error('账号或密码错误');
  const token = randomAlphaNum(48);
  await env.DB.prepare('INSERT INTO admin_sessions (token, cookie_id, expires_at) VALUES (?, ?, ?)').bind(token, row.id, Date.now() + 7 * 86400000).run();
  return new Response(JSON.stringify({ role: row.role, cookie: `${row.id}#${row.secret}` }), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': `tdao_admin=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800` },
  });
}

async function logout(ctx) {
  const { env, request } = ctx;
  const token = getCookie(request, 'tdao_admin');
  if (token) await env.DB.prepare('DELETE FROM admin_sessions WHERE token = ?').bind(token).run();
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'tdao_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' },
  });
}

async function hideItem(ctx, action) {
  const { env, url, cookieRaw } = ctx;
  await requireStaff(env, cookieRaw);
  const id = Number(url.searchParams.get('id'));
  const table = action === 'hide_post' ? 'posts' : 'replies';
  await env.DB.prepare(`UPDATE ${table} SET is_hidden = 1 WHERE id = ?`).bind(id).run();
  return { ok: true };
}

async function pinPost(ctx) {
  const { env, url, cookieRaw } = ctx;
  await requireStaff(env, cookieRaw);
  const id = Number(url.searchParams.get('id'));
  const pin = Number(url.searchParams.get('pin'));
  await env.DB.prepare('UPDATE posts SET is_pinned = ? WHERE id = ?').bind(pin, id).run();
  return { ok: true };
}

async function banItem(ctx) {
  const { env, url, cookieRaw } = ctx;
  await requireStaff(env, cookieRaw);
  const type = url.searchParams.get('type');
  const val = url.searchParams.get('val');
  const days = Number(url.searchParams.get('days') || 7);
  await env.DB.prepare('INSERT OR REPLACE INTO bans (type, val, expires_at) VALUES (?, ?, ?)').bind(type, val, Date.now() + days * 86400000).run();
  return { ok: true };
}

async function deletePost(ctx) {
  const { env, url, cookieRaw } = ctx;
  await requireSuper(env, cookieRaw);
  const id = Number(url.searchParams.get('id'));
  await env.DB.prepare('DELETE FROM replies WHERE post_id = ?').bind(id).run();
  await env.DB.prepare('DELETE FROM posts WHERE id = ?').bind(id).run();
  return { ok: true };
}

async function deleteReply(ctx) {
  const { env, url, cookieRaw } = ctx;
  await requireSuper(env, cookieRaw);
  const id = Number(url.searchParams.get('id'));
  await env.DB.prepare('DELETE FROM replies WHERE id = ?').bind(id).run();
  return { ok: true };
}

async function getStaffs(ctx) {
  const { env, cookieRaw } = ctx;
  await requireSuper(env, cookieRaw);
  const { results } = await env.DB.prepare("SELECT id, role, display, created_at FROM cookies WHERE role IN ('admin', 'mod', 'super')").all();
  return results;
}

async function deleteStaff(ctx) {
  const { env, url, cookieRaw } = ctx;
  await requireSuper(env, cookieRaw);
  const id = url.searchParams.get('id');
  if (id === parseCookie(cookieRaw).id) throw new Error('不能删除自己的超级管理员账号');
  await env.DB.prepare("DELETE FROM cookies WHERE id = ? AND role != 'super'").bind(id).run();
  return { ok: true };
}

function isSafeUrl(u) {
  return typeof u === 'string' && /^https?:\/\/[^\s]+$/i.test(u) && /\.(jpe?g|png|gif|webp|bmp)$/i.test(u.split('#')[0].split('?')[0]);
}

function randomAlphaNum(len) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  for (const b of arr) out += chars[b % chars.length];
  return out;
}