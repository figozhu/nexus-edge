const fs = require('node:fs');
const path = require('node:path');

/**
 * 在受信任主分支/tag 的成功构建后发布不可覆盖的版本，失败草稿支持同提交重试。
 * @param {object} options GitHub Actions 的 github/context/core；root 可在离线测试中替换。
 * @returns {Promise<object>} 发布或跳过状态；API 错误、版本冲突和不明草稿均抛错。
 * 只使用 workflow 的 GITHUB_TOKEN，不读取本机 App 令牌。实际调用必须在所有验证完成后。
 */
async function publishRelease({ github, context, core, root = process.cwd() }) {
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('只接受三段数字的稳定版本号。');
  const tag = `v${version}`;
  const tagPush = context.ref.startsWith('refs/tags/');
  if (context.eventName !== 'push' || (context.ref !== 'refs/heads/main' && context.ref !== `refs/tags/${tag}`)) {
    throw new Error('发布仅允许 main 推送或与版本一致的标签推送。');
  }
  const repo = context.repo;
  let release;
  try { release = (await github.rest.repos.getReleaseByTag({ ...repo, tag })).data; }
  catch (error) { if (error.status !== 404) throw error; }
  if (release && !release.draft) {
    // 普通后续提交仍执行全部测试和构建；只有显式提升版本号才产生新的公开版本。
    core.info(`${tag} 已发布，保留原附件。需要发布更新时，请提升 package.json 和 APP_VERSION。`);
    return { skipped: true, tag, url: release.html_url };
  }
  if (release && release.target_commitish !== context.sha) throw new Error(`${tag} 草稿属于另一个提交，请先人工核对。`);
  let ref;
  try { ref = (await github.rest.git.getRef({ ...repo, ref: `tags/${tag}` })).data; }
  catch (error) { if (error.status !== 404) throw error; }
  if (ref) {
    // 带注释标签需解引用；不移动已有标签，防止把当前附件挂到另一份源码上。
    let object = ref.object;
    for (let depth = 0; object.type === 'tag' && depth < 5; depth++) {
      object = (await github.rest.git.getTag({ ...repo, tag_sha: object.sha })).data.object;
    }
    if (object.type !== 'commit' || object.sha !== context.sha) throw new Error(`${tag} 指向另一提交，拒绝发布。`);
  } else if (tagPush) throw new Error('触发发布的标签已不存在，拒绝创建替代标签。');

  const directory = path.join(root, 'dist', 'release');
  const files = fs.readdirSync(directory).sort();
  if (!files.includes('SHA256SUMS') || files.length !== 9) throw new Error('Release 附件集合不完整。');
  if (!release) {
    release = (await github.rest.repos.createRelease({
      ...repo, tag_name: tag, target_commitish: context.sha, name: `NexusEdge ${tag}`,
      draft: true, prerelease: false, generate_release_notes: true,
    })).data;
  }
  // 仅清理同一提交尚未公开的草稿附件；全部重新上传，避免重试混入旧产物。
  const existing = await github.paginate(github.rest.repos.listReleaseAssets, { ...repo, release_id: release.id, per_page: 100 });
  if (existing.some(asset => !files.includes(asset.name))) throw new Error('草稿包含未知附件，请人工核对后重试。');
  for (const asset of existing) await github.rest.repos.deleteReleaseAsset({ ...repo, asset_id: asset.id });
  for (const name of files) {
    await github.rest.repos.uploadReleaseAsset({ ...repo, release_id: release.id, name, data: fs.readFileSync(path.join(directory, name)) });
  }
  const published = (await github.rest.repos.updateRelease({ ...repo, release_id: release.id, draft: false })).data;
  core.info(`已发布 ${tag}：${published.html_url}`);
  return { skipped: false, tag, url: published.html_url };
}

module.exports = { publishRelease };
