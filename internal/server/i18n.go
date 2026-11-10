package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
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

// langChosenCookie marks a language chosen while signed out, so the sign-in that
// follows saves it with the account. It holds no value of its own.
const langChosenCookie = "t10_locale_chosen"

const langChosenAge = 30 * 60

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
		"ago":  func(at time.Time) string { return ago(lang, time.Since(at)) },
		"join": func(items []string) string {
			if lang == langZH {
				return strings.Join(items, "、")
			}
			return strings.Join(items, ", ")
		},
	}
}

// ago says how long ago something started, which needs no time zone. Pages here run
// no script that could show the viewer's own clock.
func ago(lang string, since time.Duration) string {
	switch {
	case since < time.Minute:
		return translate(lang, "Started just now")
	case since < time.Hour:
		return translate(lang, "Started %d min ago", int(since.Minutes()))
	case since < 24*time.Hour:
		return translate(lang, "Started %d h ago", int(since.Hours()))
	}
	return translate(lang, "Started %d days ago", int(since.Hours()/24))
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
	"Platform console":            "平台控制台",
	"Apps":                        "应用",
	"Theme":                       "主题",
	"System":                      "跟随系统",
	"Light":                       "浅色",
	"Dark":                        "深色",
	"Back to %s":                  "返回%s",
	"This browser":                "当前浏览器",
	"Another browser":             "其他浏览器",
	"Open: %s":                    "已打开：%s",
	"No app open":                 "没有打开的应用",
	"Started just now":            "刚刚登录",
	"Started %d min ago":          "%d 分钟前登录",
	"Started %d h ago":            "%d 小时前登录",
	"Started %d days ago":         "%d 天前登录",
	"That browser is signed out.": "已退出该浏览器。",
	"Chat, tasks and documents":   "对话、任务和文档",
	"Workbench":                   "工作台",
	"Platform":                    "平台",
	"Where to?":                   "去哪里？",
	"On the internal network":     "仅限内部网络",
	"You're not in a tenant yet":  "您还没有加入任何租户",
	"Ask a tenant admin for an invitation link.": "请联系租户管理员获取邀请链接。",
	"Choose a workspace":                         "选择工作空间",
	"Admin":                                      "管理员",
	"Member":                                     "成员",
	"You belong to several workspaces. Which one do you want to open?": "您属于多个工作空间。要打开哪一个？",
	"Needs a second factor": "需要第二验证因素",
	"Opens in Workbench":    "在工作台中打开",
	"You administer the platform and a tenant. Each has its own place.": "您同时管理平台和租户，两者各有入口。",
	"Administration":                         "管理入口",
	"Language":                               "语言",
	"Sign-in names":                          "登录名",
	"Your account":                           "我的账户",
	"Sign out":                               "退出登录",
	"Your name":                              "您的姓名",
	"Name teammates see":                     "同事看到的姓名",
	"Name saved.":                            "姓名已保存。",
	"Use a name of 100 characters or fewer.": "姓名不能超过 100 个字符。",
	"Save":                                   "保存",

	// Values stored in English.
	"active":     "已启用",
	"inactive":   "已停用",
	"suspended":  "已暂停",
	"admin":      "管理员",
	"member":     "成员",
	"department": "部门",
	"team":       "团队",
	"success":    "成功",
	"denied":     "已拒绝",

	// Account pages.
	"Username, phone or email": "用户名、手机号或邮箱",

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

	// Results of actions.

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
	"Sign in to %s": "登录%s",
	"Property":      "物业",
	"You've signed out of all t10 apps on this browser.":              "您已退出此浏览器上的所有 t10 应用。",
	"You've been signed out. Sign in to pick up where you left off.":  "您已退出登录。重新登录后可继续之前的操作。",
	"Wrong sign-in name or password.":                                 "登录名或密码错误。",
	"Enter your code":                                                 "输入验证码",
	"Open your authenticator app and enter the 6-digit code for t10.": "打开身份验证器应用，输入 t10 的 6 位验证码。",
	"Authenticator code":                                              "身份验证器验证码",
	"Start over":                                                      "重新开始",
	"That code didn't work. Try the newest one.":                      "验证码无效，请输入最新的验证码。",
	"That took too long. Enter your password again.":                  "等待时间过长，请重新输入密码。",
	"Sign out of t10?":                                                "要退出 t10 吗？",
	"This signs you out of every t10 app on this browser.":            "这会退出此浏览器上的所有 t10 应用。",
	"That sign-out link ran out. Sign out here instead.":              "退出链接已失效，请在此退出。",
	"This browser is signed in to t10 with a different account. Sign out of that one too?": "此浏览器已用其他账户登录 t10。也要退出该账户吗？",
	"Stay signed in":                      "保持登录",
	"Too many attempts. Try again later.": "尝试次数过多，请稍后再试。",
	"Those details did not match. An account with an authenticator needs its code or a second recovery code.": "信息不匹配。已开启身份验证器的账户需要提供其验证码或第二个恢复码。",
}
