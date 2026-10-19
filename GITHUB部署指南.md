# GitHub 部署指南（把本地仓库推到你的 GitHub）

本仓库已经在你电脑上完成 `git init` 和本地提交（commit 历史已就绪），你只需要把它关联到**你自己的** GitHub 账号并推送上去即可。

---

## 0. 前置条件
- 已安装 Git（命令行输入 `git --version` 能正常显示版本）。
- 拥有 GitHub 账号（https://github.com）。

---

## 1. 设置你的 Git 身份（重要）
当前仓库的提交作者还是占位名 `Your Name`。推送前请改成你自己的名字和邮箱（只影响这个仓库）：

```bash
cd "C:/Users/deokee/Desktop/项目1：nids-project"
git config user.name  "你的真实姓名"
git config user.email "你的邮箱@example.com"
```

> 说明：已生成的 commit 作者信息不会自动变。若希望历史作者也改成你的名字，见文末「进阶：改写历史作者」。

---

## 2. 替换 README 里的署名占位
用记事本打开 `README.md`，把两处 `[你的姓名]` 替换成你的真实姓名（顶部作者行和底部 License 行）。

---

## 3. 在 GitHub 新建空仓库
1. 登录 GitHub → 右上角 **+** → **New repository**。
2. 仓库名建议：`nids-dual-engine`（或自定义）。
3. **不要**勾选 "Add a README file" / "Add .gitignore" / "Add license"（保持空仓库，避免冲突）。
4. 点击 **Create repository**，进入后复制仓库地址（HTTPS 或 SSH，例如 `https://github.com/你的用户名/nids-dual-engine.git`）。

---

## 4. 关联远程并推送
回到命令行（仍在项目目录）：

```bash
# 关联远程仓库（把 URL 换成你刚才复制的）
git remote add origin https://github.com/你的用户名/nids-dual-engine.git

# 首次推送并设置上游（当前分支名用变量自动适配 main / master）
git push -u origin $(git branch --show-current)
```

推送成功后，刷新 GitHub 页面即可看到完整代码、提交历史和目录结构。

---

## 5. 验证
```bash
git remote -v        # 应显示 origin 指向你的仓库
git log --oneline    # 应显示 7 条左右的提交历史
```
在 GitHub 页面确认：代码文件、`models/`（两个 .joblib）、`NIDS项目答辩/` 的 PPT 都已上传。

---

## 常见问题

**Q：push 时提示鉴权失败 / 弹出登录？**
A：GitHub 已不支持密码登录，需用 **Personal Access Token（PAT）** 或 **SSH Key**。
- HTTPS 方式：密码框粘贴 PAT（token 需勾选 `repo` 权限，生成地址：GitHub → Settings → Developer settings → Personal access tokens）。
- 推荐 SSH：本地生成密钥并到 GitHub → Settings → SSH and GPG keys 添加公钥，之后用 `git@github.com:用户名/仓库.git` 作为 remote URL。

**Q：分支是 master 还是 main？**
A：脚本里用 `$(git branch --show-current)` 会自动适配，无需手动指定。若想统一改为主分支名 `main`，可执行：
```bash
git branch -m main
git push -u origin main
```

**Q：以后代码改了怎么更新？**
```bash
git add -A
git commit -m "描述这次改动"
git push
```

---

## 进阶：改写历史作者为你的名字（可选）
若希望已生成的提交历史作者也显示你的名字（而非 `Your Name`），在项目目录执行：
```bash
git filter-branch -f --env-filter '
export GIT_AUTHOR_NAME="你的真实姓名"
export GIT_AUTHOR_EMAIL="你的邮箱@example.com"
export GIT_COMMITTER_NAME="你的真实姓名"
export GIT_COMMITTER_EMAIL="你的邮箱@example.com"
' -- --all
git push -u origin $(git branch --show-current) --force
```
> 注意：`--force` 会覆盖远程历史，个人新仓库无影响；若是协作仓库请勿随意 force。
