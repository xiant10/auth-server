package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
)

// The pages' languages. English strings are the keys of each catalog, so
// text with no translation stays readable.
const (
	langEN = "en"
	langZH = "zh-Hans"
)

// langCookie holds an explicit choice, which beats Accept-Language. It is not
// sensitive.
const langCookie = "t10_locale"

const langCookieAge = 365 * 24 * 60 * 60

func validLang(lang string) bool { return lang == langEN || lang == langZH }

// requestLang is the language to answer a page in.
func requestLang(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && validLang(c.Value) {
		return c.Value
	}
	return acceptedLang(r.Header.Get("Accept-Language"))
}

// acceptedLang picks the header's most preferred language that the UI has. Every
// Chinese tag gets Simplified, the only Chinese catalog.
func acceptedLang(header string) string {
	best, bestQ := langEN, 0.0
	for part := range strings.SplitSeq(header, ",") {
		tag, params, _ := strings.Cut(part, ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		lang := ""
		switch {
		case tag == "zh" || strings.HasPrefix(tag, "zh-"):
			lang = langZH
		case tag == "en" || strings.HasPrefix(tag, "en-"):
			lang = langEN
		default:
			continue
		}
		q := 1.0
		if value, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			q, _ = strconv.ParseFloat(value, 64)
		}
		if q > bestQ {
			best, bestQ = lang, q
		}
	}
	return best
}

// translate returns msg in lang, filling in any args. A translation may reorder
// them with %[2]s.
func translate(lang, msg string, args ...any) string {
	if lang == langZH {
		if zh, ok := zhText[msg]; ok {
			msg = zh
		}
	}
	if len(args) > 0 {
		return fmt.Sprintf(msg, args...)
	}
	return msg
}

// translator is the templates' t function, and lang tells them which they are.
func translator(lang string) template.FuncMap {
	return template.FuncMap{
		"t":    func(msg string, args ...any) string { return translate(lang, msg, args...) },
		"lang": func() string { return lang },
	}
}

// pagesFor returns the template set for lang.
func pagesFor(lang string) *template.Template {
	if lang == langZH {
		return pagesZH
	}
	return pages
}

// zhText is every page in Simplified Chinese. Everything a person reads there
// must be here: TestChineseCatalogIsComplete fails on a string that isn't.
var zhText = map[string]string{
	// Frame and navigation.
	"t10 admin":                             "t10 管理后台",
	"Admin console":                         "管理后台",
	"Admin":                                 "管理员",
	"Administration":                        "管理导航",
	"Show the menu":                         "显示菜单",
	"Menu":                                  "菜单",
	"Language":                              "语言",
	"Overview":                              "概览",
	"Platform":                              "平台",
	"Tenants":                               "租户",
	"Users":                                 "用户",
	"Sign-in names":                         "登录名",
	"Audit log":                             "审计日志",
	"Agent control":                         "智能体控制台",
	"Your tenants":                          "我的租户",
	"Your account":                          "我的账户",
	"Sign out":                              "退出登录",
	"Go to your account":                    "前往我的账户",
	"Platform-wide":                         "全平台范围",
	"Changes here can affect every tenant.": "此处的更改可能影响所有租户。",
	"Tenant: %s":                            "租户：%s",
	"Changes here apply to this tenant only.": "此处的更改仅对该租户生效。",
	"Your name":                              "您的姓名",
	"Name teammates see":                     "同事看到的姓名",
	"Name saved.":                            "姓名已保存。",
	"Use a name of 100 characters or fewer.": "姓名不能超过 100 个字符。",
	"Copy":                                   "复制",
	"Copied":                                 "已复制",
	"Manage":                                 "管理",
	"None":                                   "无",
	"None.":                                  "暂无。",
	"you":                                    "我",
	"Search":                                 "搜索",
	"Name":                                   "名称",
	"Role":                                   "角色",
	"Status":                                 "状态",
	"Save":                                   "保存",
	"Save changes":                           "保存更改",
	"Unit":                                   "单元",
	"Manager":                                "上级",
	"Member":                                 "成员",
	"Reactivate":                             "重新启用",

	// Values stored in English.
	"active":         "已启用",
	"inactive":       "已停用",
	"suspended":      "已暂停",
	"admin":          "管理员",
	"member":         "成员",
	"department":     "部门",
	"team":           "团队",
	"platform admin": "平台管理员",
	"stopped":        "已停止",
	"ended":          "已结束",
	"success":        "成功",
	"denied":         "已拒绝",

	// Overview.
	"Suspended":      "已暂停",
	"You administer": "我管理的租户",
	"Every tenant":   "所有租户",
	"Manage tenants and users, release sign-in names and read the platform audit log.": "管理租户和用户、释放登录名，并查看平台审计日志。",
	"You'll be asked to sign in again with your authenticator.":                        "系统会要求您使用身份验证器重新登录。",
	"Tenants you administer": "我管理的租户",

	// Tenants.
	"Find a tenant":                  "查找租户",
	"Name or ID":                     "名称或 ID",
	"Tenant":                         "租户",
	"Active members":                 "已启用成员",
	"Active admins":                  "已启用管理员",
	"Second factor":                  "第二重验证",
	"Required":                       "必需",
	"Optional":                       "可选",
	"No tenant matches that search.": "没有符合搜索条件的租户。",
	"No tenants yet.":                "暂无租户。",
	"Create a tenant":                "创建租户",
	"ID (optional)":                  "ID（可选）",
	"Create tenant":                  "创建租户",

	// Users.
	"Find a user":                     "查找用户",
	"Sign-in name, or a full user ID": "登录名或完整的用户 ID",
	"User":                            "用户",
	"Active tenants":                  "已启用的租户",
	"Created":                         "创建时间",
	"1 active tenant · Created %s":    "1 个已启用的租户 · 创建于 %s",
	"%d active tenants · Created %s":  "%d 个已启用的租户 · 创建于 %s",
	"Remove the platform role before suspending this user.": "暂停此用户前，请先移除其平台角色。",
	"Suspend this user": "暂停此用户",
	"Suspending blocks sign-in in every tenant, ends all sessions and stops their agents. Tokens already issued last up to 5 minutes.": "暂停后，该用户将无法登录任何租户，所有会话都会结束，其智能体也会停止。已签发的令牌最长仍有效 5 分钟。",
	"Yes, suspend %s":                "确认暂停 %s",
	"Yes, suspend this user":         "确认暂停此用户",
	"Remove the platform role":       "移除平台角色",
	"Yes, remove my platform access": "确认移除我的平台权限",
	"Yes, remove platform access":    "确认移除平台权限",
	"Make a platform admin":          "设为平台管理员",
	"This reaches every tenant. They'll need an authenticator before they can use it.": "此角色可访问所有租户。对方需要先启用身份验证器才能使用。",
	"Yes, make %s a platform admin":        "确认将 %s 设为平台管理员",
	"Yes, make this user a platform admin": "确认将此用户设为平台管理员",
	"No user matches that search.":         "没有符合搜索条件的用户。",
	"No users yet.":                        "暂无用户。",

	// Sign-in names.
	"Release a name": "释放登录名",
	"For disputes. The holder keeps their account, but may be left with no name to sign in with.": "用于处理争议。持有人会保留账户，但可能因此没有可用于登录的名称。",
	"Username, phone or email": "用户名、手机号或邮箱",
	"Release name":             "释放登录名",

	// Audit.
	"Time (UTC)":            "时间 (UTC)",
	"Actor":                 "操作者",
	"Action":                "操作",
	"Target":                "目标",
	"Outcome":               "结果",
	"Nothing recorded yet.": "暂无记录。",
	"The newest 100 platform entries. Each tenant's activity is on its own page.": "最新的 100 条平台记录。各租户的活动请在其各自页面查看。",

	// Tenant page.
	"Members":            "成员",
	"Organization":       "组织架构",
	"Agents":             "智能体",
	"Invite":             "邀请",
	"Security":           "安全",
	"Activity":           "活动",
	"Reset link for %s.": "%s 的重置链接。",
	"Reset link.":        "重置链接。",
	"Send it to them now. It won't be shown again, works once and expires in 30 minutes. Their authenticator stays on.": "请立即发送给对方。此链接不会再次显示，仅可使用一次，30 分钟后失效。对方的身份验证器保持开启。",
	"Reports to %s":              "上级：%s",
	"Joined %s":                  "加入于 %s",
	"Joined":                     "加入时间",
	"Active":                     "已启用",
	"Inactive":                   "已停用",
	"Save placement":             "保存组织位置",
	"Create password reset link": "创建密码重置链接",
	"No members yet.":            "暂无成员。",
	"Invite the first one.":      "邀请第一位成员。",
	"Platform action":            "平台操作",
	"Add a member by user ID":    "通过用户 ID 添加成员",
	"Use this when an invitation won't do, such as giving a new tenant its first admin.": "适用于无法使用邀请的情况，例如为新租户添加第一位管理员。",
	"User ID":    "用户 ID",
	"Add member": "添加成员",

	// Organization tab.
	"Units": "组织单元",
	"Services read this tree, and each member's manager, to decide what people can see. Set someone's unit and manager from their row on the Members tab.": "各服务会读取此组织树及每位成员的上级，以决定成员可见的内容。请在“成员”标签页的对应行中设置成员的单元和上级。",
	"1 active member":                        "1 位已启用成员",
	"%d active members":                      "%d 位已启用成员",
	"Kind":                                   "类型",
	"Department":                             "部门",
	"Team":                                   "团队",
	"Parent":                                 "上级单元",
	"Remove this unit":                       "移除此单元",
	"No units yet. Add the first one below.": "暂无组织单元。请添加第一个单元。",
	"Add a unit":                             "添加单元",
	"Sales":                                  "销售部",
	"Add unit":                               "添加单元",

	// Agents tab.
	"Agent access": "智能体访问权限",
	"Each call or agent run holds its own grant, which stays active until it ends or is stopped, even after the call does. Stopping one also stops every agent it started. Tokens already issued last up to 5 minutes.": "每次通话或智能体运行都持有独立的授权，该授权在结束或被停止前一直有效，即使通话已结束。停止某项授权也会停止由它启动的所有智能体。已签发的令牌最长仍有效 5 分钟。",
	"started by another agent": "由其他智能体启动",
	"Started (UTC)":            "开始时间 (UTC)",
	"Ends (UTC)":               "结束时间 (UTC)",
	"Stop":                     "停止",
	"No agents have run for this tenant yet.": "此租户尚未运行过智能体。",

	// Invite tab.
	"Invitation ready.": "邀请已就绪。",
	"Send one link to one person. It won't be shown again, works once and expires in 7 days.": "一个链接只发给一个人。此链接不会再次显示，仅可使用一次，7 天后失效。",
	"For someone new":             "发给新用户",
	"For someone with an account": "发给已有账户的用户",
	"Invite someone":              "邀请成员",
	"Create a link and send it yourself. t10 never contacts people for you.": "请创建链接后自行发送。t10 不会代您联系任何人。",
	"Create invitation link": "创建邀请链接",

	// Security tab.
	"Require a second factor for this tenant": "要求此租户启用第二重验证",
	"Members without an authenticator or an MFA-capable device can't get a token for this tenant until they add one.": "未配置身份验证器或支持多重验证设备的成员，在添加之前无法获取此租户的令牌。",
	"Tenant status": "租户状态",
	"Suspending stops new tokens and room admission for every member. Tokens already issued last up to 5 minutes.": "暂停后，所有成员都无法获取新令牌或进入房间。已签发的令牌最长仍有效 5 分钟。",
	"Reactivating lets members get tokens again.":                                                                  "重新启用后，成员可以再次获取令牌。",
	"Suspend this tenant": "暂停此租户",

	// Activity tab.
	"Recent activity": "最近活动",

	// Account pages, which the admin popup shows.
	"Close":                           "关闭",
	"Open as a full page":             "在完整页面中打开",
	"Account":                         "账户",
	"username":                        "用户名",
	"phone":                           "手机号",
	"email":                           "邮箱",
	"%s, unverified":                  "%s，未验证",
	"Add a name":                      "添加登录名",
	"New name":                        "新登录名",
	"Add name":                        "添加登录名",
	"Remove a name":                   "移除登录名",
	"Name to remove":                  "要移除的登录名",
	"Remove name":                     "移除登录名",
	"Current password":                "当前密码",
	"Authenticator code (if enabled)": "身份验证器验证码（如已开启）",
	"Password":                        "密码",
	"Change your password":            "修改密码",
	"New password":                    "新密码",
	"Change password":                 "修改密码",
	"Authenticator":                   "身份验证器",
	"On":                              "已开启",
	"Off":                             "已关闭",
	"Turn off":                        "关闭",
	"Turn on":                         "开启",
	"Set up an authenticator":         "设置身份验证器",
	"Set up authenticator":            "设置身份验证器",
	"Continue":                        "继续",
	"Devices":                         "设备",
	"Remove this device":              "移除此设备",
	"Remove device":                   "移除设备",
	"No app enrolled.":                "尚未注册任何应用。",
	"Recovery codes":                  "恢复码",
	"%d left":                         "剩余 %d 个",
	"Replace all codes":               "替换全部恢复码",
	"Sessions":                        "会话",
	"Signs you out here and on your other browsers and clients.": "退出此处及您的其他浏览器和客户端的登录。",
	"Sign out everywhere": "退出所有设备",
	"Save these recovery codes now. They are shown once, and each works once.": "请立即保存这些恢复码。它们只显示一次，每个只能使用一次。",
	"I have saved them": "我已保存",
	"Scan this with your authenticator app, then enter the code it shows.": "请用身份验证器应用扫描此二维码，然后输入显示的验证码。",
	"QR code for your authenticator app":                                   "身份验证器应用的二维码",
	"Can't scan it?":                                                       "无法扫描？",
	"Enter this secret by hand:":                                           "请手动输入此密钥：",
	"Open in an authenticator app":                                         "在身份验证器应用中打开",
	"Code":                                                                 "验证码",
	"Password changed. Your other sessions have ended.":                    "密码已修改。您的其他会话已结束。",
	"Name added.":                                                          "登录名已添加。",
	"Name removed.":                                                        "登录名已移除。",
	"Authenticator on. Your other sessions have ended.":                    "身份验证器已开启。您的其他会话已结束。",
	"Authenticator off.":                                                   "身份验证器已关闭。",
	"Device removed.":                                                      "设备已移除。",
	"Unknown action.":                                                      "未知操作。",
	"Wrong password or code.":                                              "密码或验证码错误。",
	"Use a longer, less common password of at least 10 characters.": "请使用至少 10 个字符、更长且不常见的密码。",
	"That is not a valid username, phone number or email.":          "这不是有效的用户名、手机号或邮箱。",
	"That sign-in name is taken.":                                   "该登录名已被占用。",
	"Keep at least one sign-in name.":                               "请至少保留一个登录名。",
	"That device is already removed.":                               "该设备已被移除。",
	"Your role or tenant requires an authenticator.":                "您的角色或租户要求使用身份验证器。",

	// Refusals.
	"No access": "无权访问",
	"Not found": "未找到",
	"You don't have admin access to this page.": "您没有此页面的管理权限。",
	"You don't administer any tenant.":          "您没有管理任何租户。",
	"No such tenant.":                           "此租户不存在。",
	"This tenant requires a second factor. Turn on an authenticator, then sign in with it.":       "此租户要求第二重验证。请先开启身份验证器，然后使用它登录。",
	"Platform admins need an authenticator. Turn one on from your account, then sign in with it.": "平台管理员需要身份验证器。请在账户中开启，然后使用它登录。",

	// Results of actions.
	"Tenant active.":    "租户已启用。",
	"Tenant suspended.": "租户已暂停。",
	"A tenant needs at least one active admin. Promote someone else first.": "租户至少需要一位已启用的管理员。请先提升其他成员。",
	"That already exists.":          "该项已存在。",
	"No such tenant, user or unit.": "租户、用户或单元不存在。",
	"That value isn't valid.":       "该值无效。",
	"That would put someone under themselves. Change the other person or unit first.": "这会让某人或某单元隶属于自身。请先更改另一方。",
	"Move this unit's members and child units first.":                                 "请先移走此单元的成员和下级单元。",
	"No such agent grant in this tenant.":                                             "此租户中没有该智能体授权。",
	"The platform needs at least one admin. Add another one first.":                   "平台至少需要一位管理员。请先添加另一位。",
	"Reactivate this user first.":                                                     "请先重新启用此用户。",
	"Remove this user's platform role first.":                                         "请先移除此用户的平台角色。",
	"No such user.":                       "用户不存在。",
	"No account holds that sign-in name.": "没有账户持有该登录名。",
	"Sign-in name released.":              "登录名已释放。",
	"User reactivated. They need to sign in again, and stopped agents stay stopped.":        "用户已重新启用。对方需要重新登录，已停止的智能体不会恢复。",
	"User suspended and signed out everywhere. Tokens already issued last up to 5 minutes.": "用户已暂停，并已在所有设备上退出登录。已签发的令牌最长仍有效 5 分钟。",
	"Platform role added. They need an authenticator before they can use it.":               "已添加平台角色。对方需要先启用身份验证器才能使用。",
	"Platform role removed.": "已移除平台角色。",
	"Turn on an authenticator and sign in with it first, or this setting would lock you out of this page.": "请先开启身份验证器并使用它登录，否则此设置会使您无法访问此页面。",
	"Second factor is now optional.": "第二重验证现为可选。",
	"Second factor is now required. Members without one can't get a token for this tenant.": "第二重验证现为必需。未配置的成员无法获取此租户的令牌。",
	"Member updated.": "成员已更新。",
	"Only a platform admin can reset this account, because it's an admin or also belongs to another tenant.": "只有平台管理员才能重置此账户，因为它是管理员账户或同时属于其他租户。",
	"Member added.":      "成员已添加。",
	"Placement updated.": "组织位置已更新。",
	"Unit added.":        "单元已添加。",
	"Unit updated.":      "单元已更新。",
	"Unit removed.":      "单元已移除。",
	"Agent access stopped. Tokens already issued last up to 5 minutes.": "智能体访问已停止。已签发的令牌最长仍有效 5 分钟。",

	// Signing in, registering and recovering.
	"Sign in":                             "登录",
	"Sign-in failed":                      "登录失败",
	"Create an account":                   "创建账户",
	"Create account":                      "创建账户",
	"Lost your password?":                 "忘记密码？",
	"Already have an account?":            "已有账户？",
	"Or scan with the t10 app":            "或使用 t10 应用扫码",
	"QR code to sign in with the t10 app": "用于通过 t10 应用登录的二维码",
	"Check the request in the app before you approve it.": "批准前，请先在应用中核对登录请求。",
	"Approve the sign-in in the app.":                     "请在应用中批准此次登录。",
	"Your name, as teammates will see it":                 "您的姓名（同事将看到此名称）",
	"Password (10 characters or more)":                    "密码（至少 10 个字符）",
	"Sign-in names are not verified, and we never use them to contact you. Keep the recovery codes shown next: they are how you get back in.": "登录名不会经过验证，我们也绝不会用它联系您。请保存接下来显示的恢复码：这是您找回账户的方式。",
	"Registration is by invitation. Ask your tenant admin for a link.":                                                                        "仅限受邀注册。请向租户管理员索取链接。",
	"Recover account":                "找回账户",
	"Recovery code":                  "恢复码",
	"Authenticator code, if enabled": "身份验证器验证码（如已开启）",
	"Or a second recovery code, if you lost your authenticator": "如果身份验证器已丢失，可改填第二个恢复码",
	"Reset password":                          "重置密码",
	"Resetting signs you out everywhere.":     "重置后，您将在所有设备上退出登录。",
	"Set a new password":                      "设置新密码",
	"Set password":                            "设置密码",
	"Password changed":                        "密码已修改",
	"You are signed out everywhere.":          "您已在所有设备上退出登录。",
	"Join tenant":                             "加入租户",
	"Join the tenant this invitation is for?": "要加入此邀请对应的租户吗？",
	"Join": "加入",
	"You are already a member of this tenant.":     "您已经是此租户的成员。",
	"This invitation is invalid, used or expired.": "此邀请无效、已使用或已过期。",
	"This link is invalid, used or expired.":       "此链接无效、已使用或已过期。",
	"Unknown client or redirect address.":          "未知的客户端或重定向地址。",
	"Sign in again to confirm it's you. Platform actions need an authenticator code from the last 15 minutes.": "请重新登录以确认是您本人。平台操作需要最近 15 分钟内的身份验证器验证码。",
	"You're signed out.":                                       "您已退出登录。",
	"Wrong sign-in name, password or code.":                    "登录名、密码或验证码错误。",
	"Enter your password again, with your authenticator code.": "请重新输入密码，并填写身份验证器验证码。",
	"Too many attempts. Try again later.":                      "尝试次数过多，请稍后再试。",
	"Those details did not match. An account with an authenticator needs its code or a second recovery code.": "信息不匹配。已开启身份验证器的账户需要提供其验证码或第二个恢复码。",
}
