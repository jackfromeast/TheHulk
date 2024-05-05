/**
* @name DOM-Clobbering-hackmd.io-a40ede4cec
* @description Finding potential DOM clobbering vulnerabilities with the identified cloudable sources
* @kind path-problem
* @problem.severity warning
* @security-severity 6.1
* @precision high
* @id js/xss-through-dom
* @tags security
*       external/cwe/cwe-079
*/
import javascript
import DataFlow::PathGraph
import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom
import semmle.javascript.security.dataflow.DomBasedXssCustomizations
        
class IdentifiedClobberableSourceWinTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceWinTypeOne() {
        exists(DataFlow::PropRead propRead |
        exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
        (   // id=1, type=WIN-TYPE-1, prop=domain 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 37 and loc.getEndLine() = 37 and
            loc.getStartColumn() <= 17 and loc.getEndColumn() >= 17
        ) or 
        (   // id=2, type=WIN-TYPE-1, prop=urlpath 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 38 and loc.getEndLine() = 38 and
            loc.getStartColumn() <= 18 and loc.getEndColumn() >= 18
        ) or 
        (   // id=3, type=WIN-TYPE-1, prop=debug 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=4, type=WIN-TYPE-1, prop=version 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 40 and loc.getEndLine() = 40 and
            loc.getStartColumn() <= 18 and loc.getEndColumn() >= 18
        ) or 
        (   // id=5, type=WIN-TYPE-1, prop=brand 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=6, type=WIN-TYPE-1, prop=GOOGLE_API_KEY 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=7, type=WIN-TYPE-1, prop=GOOGLE_CLIENT_ID 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 46 and loc.getEndLine() = 46 and
            loc.getStartColumn() <= 27 and loc.getEndColumn() >= 27
        ) or 
        (   // id=8, type=WIN-TYPE-1, prop=DROPBOX_APP_KEY 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 47 and loc.getEndLine() = 47 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=9, type=WIN-TYPE-1, prop=PLANTUML_SERVER 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 49 and loc.getEndLine() = 49 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=10, type=WIN-TYPE-1, prop=ASSET_URL 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 51 and loc.getEndLine() = 51 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=11, type=WIN-TYPE-1, prop=USER_CAN_CREATE_TEAM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=12, type=WIN-TYPE-1, prop=USER_CAN_DELETE_ACCOUNT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 34 and loc.getEndColumn() >= 34
        ) or 
        (   // id=13, type=WIN-TYPE-1, prop=USER_DELETE_ACCOUNT_VIA_EMAIL 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 55 and loc.getEndLine() = 55 and
            loc.getStartColumn() <= 40 and loc.getEndColumn() >= 40
        ) or 
        (   // id=14, type=WIN-TYPE-1, prop=PAYMENT_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 56 and loc.getEndLine() = 56 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=15, type=WIN-TYPE-1, prop=PAYMENT_PROMOTION_BANNER_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 57 and loc.getEndLine() = 57 and
            loc.getStartColumn() <= 43 and loc.getEndColumn() >= 43
        ) or 
        (   // id=16, type=WIN-TYPE-1, prop=GITHUB_SYNC_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=17, type=WIN-TYPE-1, prop=GITLAB_SYNC_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=18, type=WIN-TYPE-1, prop=GITLAB_SYNC_BASE_URL 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=19, type=WIN-TYPE-1, prop=VCS_SYNC_MODE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 61 and loc.getEndLine() = 61 and
            loc.getStartColumn() <= 24 and loc.getEndColumn() >= 24
        ) or 
        (   // id=20, type=WIN-TYPE-1, prop=VCS_PROVIDER_NAME 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 62 and loc.getEndLine() = 62 and
            loc.getStartColumn() <= 28 and loc.getEndColumn() >= 28
        ) or 
        (   // id=21, type=WIN-TYPE-1, prop=FREE_TEAM_NUM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 63 and loc.getEndLine() = 63 and
            loc.getStartColumn() <= 24 and loc.getEndColumn() >= 24
        ) or 
        (   // id=22, type=WIN-TYPE-1, prop=FREE_TEAM_MEMBER_NUM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 64 and loc.getEndLine() = 64 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=23, type=WIN-TYPE-1, prop=FREE_PUBLIC_TEAM_NUM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 65 and loc.getEndLine() = 65 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=24, type=WIN-TYPE-1, prop=EE_SITE_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 67 and loc.getEndLine() = 67 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=25, type=WIN-TYPE-1, prop=EE_SITE_NAME 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 68 and loc.getEndLine() = 68 and
            loc.getStartColumn() <= 23 and loc.getEndColumn() >= 23
        ) or 
        (   // id=26, type=WIN-TYPE-1, prop=EE_SITE_LINK 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 69 and loc.getEndLine() = 69 and
            loc.getStartColumn() <= 23 and loc.getEndColumn() >= 23
        ) or 
        (   // id=27, type=WIN-TYPE-1, prop=EESITE_INFO 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 70 and loc.getEndLine() = 70 and
            loc.getStartColumn() <= 22 and loc.getEndColumn() >= 22
        ) or 
        (   // id=28, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 71 and loc.getEndLine() = 71 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=29, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_TEAM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=30, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_NOTE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=31, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_VIEW_PERMISSION 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 74 and loc.getEndLine() = 74 and
            loc.getStartColumn() <= 47 and loc.getEndColumn() >= 47
        ) or 
        (   // id=32, type=WIN-TYPE-1, prop=ALLOW_ANONYMOUS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 76 and loc.getEndLine() = 76 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=33, type=WIN-TYPE-1, prop=ALLOW_ANONYMOUS_EDIT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 77 and loc.getEndLine() = 77 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=34, type=WIN-TYPE-1, prop=PUBLIC_OVERVIEW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=35, type=WIN-TYPE-1, prop=INTERNAL_PUBLIC_OVERVIEW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=36, type=WIN-TYPE-1, prop=FULL_TEXT_SEARCH_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 34 and loc.getEndColumn() >= 34
        ) or 
        (   // id=37, type=WIN-TYPE-1, prop=ALGOLIA_SEARCH_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 81 and loc.getEndLine() = 81 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=38, type=WIN-TYPE-1, prop=MARKETING_EMAIL_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 82 and loc.getEndLine() = 82 and
            loc.getStartColumn() <= 33 and loc.getEndColumn() >= 33
        ) or 
        (   // id=39, type=WIN-TYPE-1, prop=RECAPTCHA_SCORE_KEY 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 85 and loc.getEndLine() = 85 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=40, type=WIN-TYPE-1, prop=WALLET_CONNECT_PROJECT_ID 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 89 and loc.getEndLine() = 89 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=41, type=WIN-TYPE-1, prop=API_MANAGEMENT_UI_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 91 and loc.getEndLine() = 91 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=42, type=WIN-TYPE-1, prop=FEEDBACK_UI_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 92 and loc.getEndLine() = 92 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=43, type=WIN-TYPE-1, prop=PUBLISH_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=44, type=WIN-TYPE-1, prop=SHOW_HOT_NOTES 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=45, type=WIN-TYPE-1, prop=HOT_NOTES_TIME_TYPE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 102 and loc.getEndLine() = 102 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=46, type=WIN-TYPE-1, prop=SHOW_OVERVIEW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 106 and loc.getEndLine() = 106 and
            loc.getStartColumn() <= 24 and loc.getEndColumn() >= 24
        ) or 
        (   // id=47, type=WIN-TYPE-1, prop=TRASH_NOTE_DELETE_AFTER_FREE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 131 and loc.getEndLine() = 131 and
            loc.getStartColumn() <= 39 and loc.getEndColumn() >= 39
        ) or 
        (   // id=48, type=WIN-TYPE-1, prop=TRASH_NOTE_DELETE_AFTER_PAID 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 132 and loc.getEndLine() = 132 and
            loc.getStartColumn() <= 39 and loc.getEndColumn() >= 39
        ) or 
        (   // id=49, type=WIN-TYPE-1, prop=ENABLED_PREVIEW_FEATURE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 135 and loc.getEndLine() = 135 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=50, type=WIN-TYPE-1, prop=IMGUR_FALLBACK_CDN 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 141 and loc.getEndLine() = 141 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=51, type=WIN-TYPE-1, prop=CLOUD_META_UI 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=52, type=WIN-TYPE-1, prop=CLOUD_META_API 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 148 and loc.getEndLine() = 148 and
            loc.getStartColumn() <= 27 and loc.getEndColumn() >= 27
        ) or 
        (   // id=53, type=WIN-TYPE-1, prop=CLOUD_META_MIGRATION 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 151 and loc.getEndLine() = 151 and
            loc.getStartColumn() <= 33 and loc.getEndColumn() >= 33
        ) or 
        (   // id=54, type=WIN-TYPE-1, prop=YAML_METADATA_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 154 and loc.getEndLine() = 154 and
            loc.getStartColumn() <= 34 and loc.getEndColumn() >= 34
        ) or 
        (   // id=55, type=WIN-TYPE-1, prop=NOTE_CAPACITY_LIMIT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 158 and loc.getEndLine() = 158 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=56, type=WIN-TYPE-1, prop=DOCUMENT_MAX_LENGTH 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 162 and loc.getEndLine() = 162 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=57, type=WIN-TYPE-1, prop=SOCIAL_NETWORK_FEATURES_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 166 and loc.getEndLine() = 166 and
            loc.getStartColumn() <= 44 and loc.getEndColumn() >= 44
        ) or 
        (   // id=58, type=WIN-TYPE-1, prop=PUBLISHMENT_MODERATION_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 170 and loc.getEndLine() = 170 and
            loc.getStartColumn() <= 43 and loc.getEndColumn() >= 43
        ) or 
        (   // id=59, type=WIN-TYPE-1, prop=SUGGEST_EDIT_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 175 and loc.getEndLine() = 175 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=60, type=WIN-TYPE-1, prop=REALTIME_CLIENT_WITH_CREDENTIALS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 179 and loc.getEndLine() = 179 and
            loc.getStartColumn() <= 45 and loc.getEndColumn() >= 45
        ) or 
        (   // id=61, type=WIN-TYPE-1, prop=dataLayer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 81 and loc.getEndColumn() >= 81
        ) or 
        (   // id=62, type=WIN-TYPE-1, prop=dataLayer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 79 and loc.getEndColumn() >= 79
        ) or 
        (   // id=66, type=WIN-TYPE-1, prop=___grecaptcha_cfg 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 103 and loc.getEndColumn() >= 103
        ) or 
        (   // id=67, type=WIN-TYPE-1, prop=___grecaptcha_cfg 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 101 and loc.getEndColumn() >= 101
        ) or 
        (   // id=68, type=WIN-TYPE-1, prop=grecaptcha 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 153 and loc.getEndColumn() >= 153
        ) or 
        (   // id=69, type=WIN-TYPE-1, prop=grecaptcha 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 151 and loc.getEndColumn() >= 151
        ) or 
        (   // id=70, type=WIN-TYPE-1, prop=__recaptcha_api 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 267 and loc.getEndColumn() >= 267
        ) or 
        (   // id=71, type=WIN-TYPE-1, prop=__google_recaptcha_client 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 540 and loc.getEndColumn() >= 540
        ) or 
        (   // id=80, type=WIN-TYPE-1, prop=plausible 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 217 and loc.getEndLine() = 217 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=81, type=WIN-TYPE-1, prop=plausible 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 217 and loc.getEndLine() = 217 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=140, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 30 and loc.getEndLine() = 30 and
            loc.getStartColumn() <= 384 and loc.getEndColumn() >= 384
        ) or 
        (   // id=141, type=WIN-TYPE-1, prop=CLOSURE_FLAGS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 662 and loc.getEndColumn() >= 662
        ) or 
        (   // id=149, type=WIN-TYPE-1, prop=google_tag_manager 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 411 and loc.getEndColumn() >= 411
        ) or 
        (   // id=150, type=WIN-TYPE-1, prop=google_tag_manager 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 408 and loc.getEndColumn() >= 408
        ) or 
        (   // id=153, type=WIN-TYPE-1, prop=__TAGGY_INSTALLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 358 and loc.getEndLine() = 358 and
            loc.getStartColumn() <= 111 and loc.getEndColumn() >= 111
        ) or 
        (   // id=159, type=WIN-TYPE-1, prop=__tcfapi 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 148 and loc.getEndLine() = 148 and
            loc.getStartColumn() <= 66 and loc.getEndColumn() >= 66
        ) or 
        (   // id=160, type=WIN-TYPE-1, prop=__tcfapiLocator 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 152 and loc.getEndLine() = 152 and
            loc.getStartColumn() <= 483 and loc.getEndColumn() >= 483
        ) or 
        (   // id=163, type=WIN-TYPE-1, prop=google_tag_data 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 245 and loc.getEndColumn() >= 245
        ) or 
        (   // id=164, type=WIN-TYPE-1, prop=google_tag_data 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 253 and loc.getEndColumn() >= 253
        ) or 
        (   // id=181, type=WIN-TYPE-1, prop=GoogleAnalyticsObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 248 and loc.getEndLine() = 248 and
            loc.getStartColumn() <= 264 and loc.getEndColumn() >= 264
        ) or 
        (   // id=182, type=WIN-TYPE-1, prop=GoogleAnalyticsObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 248 and loc.getEndLine() = 248 and
            loc.getStartColumn() <= 311 and loc.getEndColumn() >= 311
        ) or 
        (   // id=183, type=WIN-TYPE-1, prop=ga 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 248 and loc.getEndLine() = 248 and
            loc.getStartColumn() <= 355 and loc.getEndColumn() >= 355
        ) or 
        (   // id=184, type=WIN-TYPE-1, prop=ga 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 248 and loc.getEndLine() = 248 and
            loc.getStartColumn() <= 455 and loc.getEndColumn() >= 455
        ) or 
        (   // id=185, type=WIN-TYPE-1, prop=gtag_enable_tcf_support 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 158 and loc.getEndLine() = 158 and
            loc.getStartColumn() <= 201 and loc.getEndColumn() >= 201
        ) or 
        (   // id=196, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/browser.sentry-cdn.com/5.15.5/bundle.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 4641 and loc.getEndColumn() >= 4641
        ) or 
        (   // id=200, type=WIN-TYPE-1, prop=__SENTRY__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/browser.sentry-cdn.com/5.15.5/bundle.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8284 and loc.getEndColumn() >= 8284
        ) or 
        (   // id=201, type=WIN-TYPE-1, prop=__SENTRY__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/browser.sentry-cdn.com/5.15.5/bundle.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8281 and loc.getEndColumn() >= 8281
        ) or 
        (   // id=207, type=WIN-TYPE-1, prop=SENTRY_RELEASE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/browser.sentry-cdn.com/5.15.5/bundle.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 55946 and loc.getEndColumn() >= 55946
        ) or 
        (   // id=293, type=WIN-TYPE-1, prop=locales 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/api/i18n.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=294, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 195 and loc.getEndLine() = 195 and
            loc.getStartColumn() <= 376 and loc.getEndColumn() >= 376
        ) or 
        (   // id=295, type=WIN-TYPE-1, prop=CLOSURE_FLAGS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 353 and loc.getEndLine() = 353 and
            loc.getStartColumn() <= 101 and loc.getEndColumn() >= 101
        ) or 
        (   // id=298, type=WIN-TYPE-1, prop=recaptcha 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 155 and loc.getEndLine() = 155 and
            loc.getStartColumn() <= 447 and loc.getEndColumn() >= 447
        ) or 
        (   // id=299, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 155 and loc.getEndLine() = 155 and
            loc.getStartColumn() <= 476 and loc.getEndColumn() >= 476
        ) or 
        (   // id=300, type=WIN-TYPE-1, prop=recaptcha 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 156 and loc.getEndLine() = 156 and
            loc.getStartColumn() <= 57 and loc.getEndColumn() >= 57
        ) or 
        (   // id=301, type=WIN-TYPE-1, prop=recaptcha 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 156 and loc.getEndLine() = 156 and
            loc.getStartColumn() <= 102 and loc.getEndColumn() >= 102
        ) or 
        (   // id=304, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 50 and loc.getEndLine() = 50 and
            loc.getStartColumn() <= 384 and loc.getEndColumn() >= 384
        ) or 
        (   // id=305, type=WIN-TYPE-1, prop=CLOSURE_FLAGS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 77 and loc.getEndLine() = 77 and
            loc.getStartColumn() <= 551 and loc.getEndColumn() >= 551
        ) or 
        (   // id=315, type=WIN-TYPE-1, prop=__TAGGY_INSTALLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 518 and loc.getEndLine() = 518 and
            loc.getStartColumn() <= 111 and loc.getEndColumn() >= 111
        ) or 
        (   // id=321, type=WIN-TYPE-1, prop=__tcfapi 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 216 and loc.getEndLine() = 216 and
            loc.getStartColumn() <= 66 and loc.getEndColumn() >= 66
        ) or 
        (   // id=322, type=WIN-TYPE-1, prop=__tcfapiLocator 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 220 and loc.getEndLine() = 220 and
            loc.getStartColumn() <= 483 and loc.getEndColumn() >= 483
        ) or 
        (   // id=341, type=WIN-TYPE-1, prop=_phantom 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/plausible.io/js/script.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 377 and loc.getEndColumn() >= 377
        ) or 
        (   // id=342, type=WIN-TYPE-1, prop=__nightmare 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/plausible.io/js/script.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 394 and loc.getEndColumn() >= 394
        ) or 
        (   // id=409, type=WIN-TYPE-1, prop=onfocusin 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 71660 and loc.getEndColumn() >= 71660
        ) or 
        (   // id=413, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 14037 and loc.getEndColumn() >= 14037
        ) or 
        (   // id=414, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 14049 and loc.getEndColumn() >= 14049
        ) or 
        (   // id=415, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 38319 and loc.getEndColumn() >= 38319
        ) or 
        (   // id=416, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 38330 and loc.getEndColumn() >= 38330
        ) or 
        (   // id=417, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 38711 and loc.getEndColumn() >= 38711
        ) or 
        (   // id=418, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 38732 and loc.getEndColumn() >= 38732
        ) or 
        (   // id=431, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 17 and loc.getEndColumn() >= 17
        ) or 
        (   // id=432, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 51 and loc.getEndColumn() >= 51
        ) or 
        (   // id=456, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26386 and loc.getEndColumn() >= 26386
        ) or 
        (   // id=457, type=WIN-TYPE-1, prop=jQuery321084623556594832671 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=458, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33332 and loc.getEndColumn() >= 33332
        ) or 
        (   // id=459, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33348 and loc.getEndColumn() >= 33348
        ) or 
        (   // id=460, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33366 and loc.getEndColumn() >= 33366
        ) or 
        (   // id=461, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33511 and loc.getEndColumn() >= 33511
        ) or 
        (   // id=474, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 14475 and loc.getEndColumn() >= 14475
        ) or 
        (   // id=478, type=WIN-TYPE-1, prop=Select2 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 2162 and loc.getEndColumn() >= 2162
        ) or 
        (   // id=479, type=WIN-TYPE-1, prop=Select2 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 66148 and loc.getEndColumn() >= 66148
        ) or 
        (   // id=480, type=WIN-TYPE-1, prop=select2 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8122 and loc.getEndColumn() >= 8122
        ) or 
        (   // id=481, type=WIN-TYPE-1, prop=select2 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8145 and loc.getEndColumn() >= 8145
        ) or 
        (   // id=486, type=WIN-TYPE-1, prop=Spinner 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7851 and loc.getEndColumn() >= 7851
        ) or 
        (   // id=487, type=WIN-TYPE-1, prop=Spinner 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7874 and loc.getEndColumn() >= 7874
        ) or 
        (   // id=489, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8975 and loc.getEndColumn() >= 8975
        ) or 
        (   // id=491, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 40859 and loc.getEndColumn() >= 40859
        ) or 
        (   // id=492, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33734 and loc.getEndColumn() >= 33734
        ) or 
        (   // id=493, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 60412 and loc.getEndColumn() >= 60412
        ) or 
        (   // id=494, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 60422 and loc.getEndColumn() >= 60422
        ) or 
        (   // id=495, type=WIN-TYPE-1, prop=core 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37155 and loc.getEndColumn() >= 37155
        ) or 
        (   // id=496, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 70395 and loc.getEndColumn() >= 70395
        ) or 
        (   // id=498, type=WIN-TYPE-1, prop=[object Object] 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 36916 and loc.getEndColumn() >= 36916
        ) or 
        (   // id=500, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 433 and loc.getEndColumn() >= 433
        ) or 
        (   // id=501, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 445 and loc.getEndColumn() >= 445
        ) or 
        (   // id=502, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 462 and loc.getEndColumn() >= 462
        ) or 
        (   // id=503, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 500 and loc.getEndColumn() >= 500
        ) or 
        (   // id=504, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48192 and loc.getEndColumn() >= 48192
        ) or 
        (   // id=506, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 45281 and loc.getEndColumn() >= 45281
        ) or 
        (   // id=507, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 77152 and loc.getEndColumn() >= 77152
        ) or 
        (   // id=508, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 77182 and loc.getEndColumn() >= 77182
        ) or 
        (   // id=509, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37006 and loc.getEndColumn() >= 37006
        ) or 
        (   // id=510, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57273 and loc.getEndColumn() >= 57273
        ) or 
        (   // id=511, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57302 and loc.getEndColumn() >= 57302
        ) or 
        (   // id=512, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57344 and loc.getEndColumn() >= 57344
        ) or 
        (   // id=513, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37006 and loc.getEndColumn() >= 37006
        ) or 
        (   // id=514, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57273 and loc.getEndColumn() >= 57273
        ) or 
        (   // id=515, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57302 and loc.getEndColumn() >= 57302
        ) or 
        (   // id=516, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57344 and loc.getEndColumn() >= 57344
        ) or 
        (   // id=517, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=518, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=519, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=520, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=521, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7322 and loc.getEndColumn() >= 7322
        ) or 
        (   // id=522, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 20677 and loc.getEndColumn() >= 20677
        ) or 
        (   // id=523, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 18455 and loc.getEndColumn() >= 18455
        ) or 
        (   // id=524, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19883 and loc.getEndColumn() >= 19883
        ) or 
        (   // id=525, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19941 and loc.getEndColumn() >= 19941
        ) or 
        (   // id=526, type=WIN-TYPE-1, prop=__esModule 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84538 and loc.getEndColumn() >= 84538
        ) or 
        (   // id=527, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84573 and loc.getEndColumn() >= 84573
        ) or 
        (   // id=528, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84963 and loc.getEndColumn() >= 84963
        ) or 
        (   // id=529, type=WIN-TYPE-1, prop=webpackChunkhackmd_enterprise_edition 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 259 and loc.getEndLine() = 259 and
            loc.getStartColumn() <= 426 and loc.getEndColumn() >= 426
        ) or 
        (   // id=530, type=WIN-TYPE-1, prop=webpackChunkhackmd_enterprise_edition 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 259 and loc.getEndLine() = 259 and
            loc.getStartColumn() <= 414 and loc.getEndColumn() >= 414
        ) or 
        (   // id=531, type=WIN-TYPE-1, prop=__REACT_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 105 and loc.getEndLine() = 105 and
            loc.getStartColumn() <= 21054 and loc.getEndColumn() >= 21054
        ) or 
        (   // id=533, type=WIN-TYPE-1, prop=MSApp 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 103 and loc.getEndLine() = 103 and
            loc.getStartColumn() <= 4237 and loc.getEndColumn() >= 4237
        ) or 
        (   // id=536, type=WIN-TYPE-1, prop=__REACT_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 105 and loc.getEndLine() = 105 and
            loc.getStartColumn() <= 12279 and loc.getEndColumn() >= 12279
        ) or 
        (   // id=537, type=WIN-TYPE-1, prop=serverurl 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 56476 and loc.getEndColumn() >= 56476
        ) or 
        (   // id=538, type=WIN-TYPE-1, prop=TYPED_ARRAY_SUPPORT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 191 and loc.getEndColumn() >= 191
        ) or 
        (   // id=542, type=WIN-TYPE-1, prop=_moment 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 44975 and loc.getEndColumn() >= 44975
        ) or 
        (   // id=559, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 5733 and loc.getEndColumn() >= 5733
        ) or 
        (   // id=560, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 9464 and loc.getEndColumn() >= 9464
        ) or 
        (   // id=561, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 46492 and loc.getEndColumn() >= 46492
        ) or 
        (   // id=562, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 46492 and loc.getEndColumn() >= 46492
        ) or 
        (   // id=563, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 46492 and loc.getEndColumn() >= 46492
        ) or 
        (   // id=564, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 46492 and loc.getEndColumn() >= 46492
        ) or 
        (   // id=565, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 41080 and loc.getEndColumn() >= 41080
        ) or 
        (   // id=569, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 26749 and loc.getEndColumn() >= 26749
        ) or 
        (   // id=570, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 26816 and loc.getEndColumn() >= 26816
        ) or 
        (   // id=571, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 15589 and loc.getEndColumn() >= 15589
        ) or 
        (   // id=573, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 35411 and loc.getEndColumn() >= 35411
        ) or 
        (   // id=631, type=WIN-TYPE-1, prop=offsetParent 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 12485 and loc.getEndColumn() >= 12485
        ) or 
        (   // id=633, type=WIN-TYPE-1, prop=jQuery321084623556594832672 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=665, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 69841 and loc.getEndColumn() >= 69841
        ) or 
        (   // id=666, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 69857 and loc.getEndColumn() >= 69857
        ) or 
        (   // id=697, type=WIN-TYPE-1, prop=resize 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70852 and loc.getEndColumn() >= 70852
        ) or 
        (   // id=705, type=WIN-TYPE-1, prop=migrateHistoryFromTempCallback 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 260 and loc.getEndLine() = 260 and
            loc.getStartColumn() <= 82786 and loc.getEndColumn() >= 82786
        ) or 
        (   // id=717, type=WIN-TYPE-1, prop=onajaxStart 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=725, type=WIN-TYPE-1, prop=onajaxSend 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=739, type=WIN-TYPE-1, prop=globalStorage 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 225 and loc.getEndLine() = 225 and
            loc.getStartColumn() <= 7435 and loc.getEndColumn() >= 7435
        ) or 
        (   // id=743, type=WIN-TYPE-1, prop=safari 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 61 and loc.getEndLine() = 61 and
            loc.getStartColumn() <= 827 and loc.getEndColumn() >= 827
        ) or 
        (   // id=753, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 74 and loc.getEndLine() = 74 and
            loc.getStartColumn() <= 49968 and loc.getEndColumn() >= 49968
        ) or 
        (   // id=754, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 74 and loc.getEndLine() = 74 and
            loc.getStartColumn() <= 44284 and loc.getEndColumn() >= 44284
        ) or 
        (   // id=755, type=WIN-TYPE-1, prop=COMMENT_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 53136 and loc.getEndColumn() >= 53136
        ) or 
        (   // id=756, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 95 and loc.getEndLine() = 95 and
            loc.getStartColumn() <= 3891 and loc.getEndColumn() >= 3891
        ) or 
        (   // id=757, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 194 and loc.getEndLine() = 194 and
            loc.getStartColumn() <= 7006 and loc.getEndColumn() >= 7006
        ) or 
        (   // id=758, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 194 and loc.getEndLine() = 194 and
            loc.getStartColumn() <= 12029 and loc.getEndColumn() >= 12029
        ) or 
        (   // id=759, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 194 and loc.getEndLine() = 194 and
            loc.getStartColumn() <= 12160 and loc.getEndColumn() >= 12160
        ) or 
        (   // id=760, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 11833 and loc.getEndColumn() >= 11833
        ) or 
        (   // id=761, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 187 and loc.getEndLine() = 187 and
            loc.getStartColumn() <= 10581 and loc.getEndColumn() >= 10581
        ) or 
        (   // id=765, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 17602 and loc.getEndColumn() >= 17602
        ) or 
        (   // id=1027, type=WIN-TYPE-1, prop=closure_listenable_591637 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 132 and loc.getEndLine() = 132 and
            loc.getStartColumn() <= 271 and loc.getEndColumn() >= 271
        ) or 
        (   // id=1028, type=WIN-TYPE-1, prop=closure_lm_26237 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 241 and loc.getEndLine() = 241 and
            loc.getStartColumn() <= 333 and loc.getEndColumn() >= 333
        ) or 
        (   // id=1029, type=WIN-TYPE-1, prop=closure_lm_26237 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 419 and loc.getEndLine() = 419 and
            loc.getStartColumn() <= 41 and loc.getEndColumn() >= 41
        ) or 
        (   // id=1597, type=WIN-TYPE-1, prop=onajaxSuccess 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=1605, type=WIN-TYPE-1, prop=onajaxComplete 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=1613, type=WIN-TYPE-1, prop=onajaxStop 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=1645, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 384 and loc.getEndColumn() >= 384
        ) or 
        (   // id=1646, type=WIN-TYPE-1, prop=CLOSURE_FLAGS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 172 and loc.getEndLine() = 172 and
            loc.getStartColumn() <= 551 and loc.getEndColumn() >= 551
        ) or 
        (   // id=1656, type=WIN-TYPE-1, prop=__TAGGY_INSTALLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 673 and loc.getEndLine() = 673 and
            loc.getStartColumn() <= 111 and loc.getEndColumn() >= 111
        ) or 
        (   // id=1662, type=WIN-TYPE-1, prop=__tcfapi 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 333 and loc.getEndLine() = 333 and
            loc.getStartColumn() <= 66 and loc.getEndColumn() >= 66
        ) or 
        (   // id=1663, type=WIN-TYPE-1, prop=__tcfapiLocator 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 337 and loc.getEndLine() = 337 and
            loc.getStartColumn() <= 483 and loc.getEndColumn() >= 483
        ) or 
        (   // id=1675, type=WIN-TYPE-1, prop=YT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 555 and loc.getEndLine() = 555 and
            loc.getStartColumn() <= 81 and loc.getEndColumn() >= 81
        ) or 
        (   // id=1676, type=WIN-TYPE-1, prop=onYouTubeIframeAPIReady 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 555 and loc.getEndLine() = 555 and
            loc.getStartColumn() <= 146 and loc.getEndColumn() >= 146
        ) or 
        (   // id=1677, type=WIN-TYPE-1, prop=onYouTubeIframeAPIReady 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 555 and loc.getEndLine() = 555 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=1679, type=WIN-TYPE-1, prop=_gaUserPrefs 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 589 and loc.getEndLine() = 589 and
            loc.getStartColumn() <= 497 and loc.getEndColumn() >= 497
        ) or 
        (   // id=1681, type=WIN-TYPE-1, prop=ga-disable-G-NGVZMM6DR6 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 589 and loc.getEndLine() = 589 and
            loc.getStartColumn() <= 608 and loc.getEndColumn() >= 608
        ) or 
        (   // id=1687, type=WIN-TYPE-1, prop=ga-disable-UA-60728495-1 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 589 and loc.getEndLine() = 589 and
            loc.getStartColumn() <= 608 and loc.getEndColumn() >= 608
        ) or 
        (   // id=1699, type=WIN-TYPE-1, prop=gaGlobal 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 563 and loc.getEndLine() = 563 and
            loc.getStartColumn() <= 345 and loc.getEndColumn() >= 345
        ) or 
        (   // id=1700, type=WIN-TYPE-1, prop=gaGlobal 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 563 and loc.getEndLine() = 563 and
            loc.getStartColumn() <= 342 and loc.getEndColumn() >= 342
        ) or 
        (   // id=1722, type=WIN-TYPE-1, prop=gtag_enable_tcf_support 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 343 and loc.getEndLine() = 343 and
            loc.getStartColumn() <= 201 and loc.getEndColumn() >= 201
        ) or 
        (   // id=1758, type=WIN-TYPE-1, prop=default_gsi 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=1759, type=WIN-TYPE-1, prop=default_gsi 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=1760, type=WIN-TYPE-1, prop=_F_toggles 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 128 and loc.getEndColumn() >= 128
        ) or 
        (   // id=1761, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 116 and loc.getEndColumn() >= 116
        ) or 
        (   // id=1762, type=WIN-TYPE-1, prop=WIZ_global_data 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 51 and loc.getEndLine() = 51 and
            loc.getStartColumn() <= 415 and loc.getEndColumn() >= 415
        ) or 
        (   // id=1764, type=WIN-TYPE-1, prop=google 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 48 and loc.getEndColumn() >= 48
        ) or 
        (   // id=1765, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 76 and loc.getEndColumn() >= 76
        ) or 
        (   // id=1766, type=WIN-TYPE-1, prop=google 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 171 and loc.getEndColumn() >= 171
        ) or 
        (   // id=1767, type=WIN-TYPE-1, prop=google 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 216 and loc.getEndColumn() >= 216
        ) or 
        (   // id=1783, type=WIN-TYPE-1, prop=closure_listenable_164304 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 410 and loc.getEndColumn() >= 410
        ) or 
        (   // id=1784, type=WIN-TYPE-1, prop=closure_lm_250469 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 63 and loc.getEndLine() = 63 and
            loc.getStartColumn() <= 142 and loc.getEndColumn() >= 142
        ) or 
        (   // id=1785, type=WIN-TYPE-1, prop=closure_lm_250469 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 98 and loc.getEndColumn() >= 98
        ) or 
        (   // id=1797, type=WIN-TYPE-1, prop=gaplugins 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 96 and loc.getEndLine() = 96 and
            loc.getStartColumn() <= 133 and loc.getEndColumn() >= 133
        ) or 
        (   // id=1798, type=WIN-TYPE-1, prop=gaplugins 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 96 and loc.getEndLine() = 96 and
            loc.getStartColumn() <= 130 and loc.getEndColumn() >= 130
        ) or 
        (   // id=1805, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 206 and loc.getEndColumn() >= 206
        ) or 
        (   // id=1806, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 307 and loc.getEndColumn() >= 307
        ) or 
        (   // id=1807, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 456 and loc.getEndColumn() >= 456
        ) or 
        (   // id=1824, type=WIN-TYPE-1, prop=_gaUserPrefs 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 532 and loc.getEndColumn() >= 532
        ) or 
        (   // id=1826, type=WIN-TYPE-1, prop=ga-disable-UA-60728495-1 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 643 and loc.getEndColumn() >= 643
        ) or 
        (   // id=1842, type=WIN-TYPE-1, prop=gaData 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 38 and loc.getEndLine() = 38 and
            loc.getStartColumn() <= 231 and loc.getEndColumn() >= 231
        ) or 
        (   // id=1843, type=WIN-TYPE-1, prop=gaData 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 38 and loc.getEndLine() = 38 and
            loc.getStartColumn() <= 228 and loc.getEndColumn() >= 228
        ) or 
        (   // id=1853, type=WIN-TYPE-1, prop=gaDevIds 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 43 and loc.getEndLine() = 43 and
            loc.getStartColumn() <= 103 and loc.getEndColumn() >= 103
        ) or 
        (   // id=1911, type=WIN-TYPE-1, prop=getBoundingClientRect 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 2251 and loc.getEndColumn() >= 2251
        ) or 
        (   // id=2172, type=WIN-TYPE-1, prop=_phantom 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/tracks.hackmd.io/js/script.manual.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 377 and loc.getEndColumn() >= 377
        ) or 
        (   // id=2173, type=WIN-TYPE-1, prop=__nightmare 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/tracks.hackmd.io/js/script.manual.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 394 and loc.getEndColumn() >= 394
        ) or 
        (   // id=2176, type=WIN-TYPE-1, prop=Zone 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 1427 and loc.getEndColumn() >= 1427
        ) or 
        (   // id=2601, type=WIN-TYPE-1, prop=onslide 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=2616, type=WIN-TYPE-1, prop=onwebkitTransitionEnd 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=2617, type=WIN-TYPE-1, prop=onslid 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=2999, type=WIN-TYPE-1, prop=onfocusin 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=3037, type=WIN-TYPE-1, prop=gtag_enable_tcf_support 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 226 and loc.getEndLine() = 226 and
            loc.getStartColumn() <= 201 and loc.getEndColumn() >= 201
        ) or 
        (   // id=4029, type=WIN-TYPE-1, prop=_phantom 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 245 and loc.getEndLine() = 245 and
            loc.getStartColumn() <= 27 and loc.getEndColumn() >= 27
        ) or 
        (   // id=4030, type=WIN-TYPE-1, prop=__nightmare 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 245 and loc.getEndLine() = 245 and
            loc.getStartColumn() <= 46 and loc.getEndColumn() >= 46
        ) or 
        (   // id=4051, type=WIN-TYPE-1, prop=onfocusout 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70653 and loc.getEndColumn() >= 70653
        ) or 
        (   // id=4721, type=WIN-TYPE-1, prop=dataLayer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 35 and loc.getEndLine() = 35 and
            loc.getStartColumn() <= 81 and loc.getEndColumn() >= 81
        ) or 
        (   // id=4722, type=WIN-TYPE-1, prop=dataLayer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 35 and loc.getEndLine() = 35 and
            loc.getStartColumn() <= 79 and loc.getEndColumn() >= 79
        ) or 
        (   // id=4735, type=WIN-TYPE-1, prop=google_tag_manager 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 152 and loc.getEndLine() = 152 and
            loc.getStartColumn() <= 422 and loc.getEndColumn() >= 422
        ) or 
        (   // id=4736, type=WIN-TYPE-1, prop=google_tag_manager 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 152 and loc.getEndLine() = 152 and
            loc.getStartColumn() <= 419 and loc.getEndColumn() >= 419
        ) or 
        (   // id=4752, type=WIN-TYPE-1, prop=google_tag_data 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 245 and loc.getEndColumn() >= 245
        ) or 
        (   // id=4753, type=WIN-TYPE-1, prop=google_tag_data 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 253 and loc.getEndColumn() >= 253
        ) or 
        (   // id=4778, type=WIN-TYPE-1, prop=plausible 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 50 and loc.getEndLine() = 50 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=4779, type=WIN-TYPE-1, prop=plausible 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 50 and loc.getEndLine() = 50 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=4999, type=WIN-TYPE-1, prop=jQuery321084437065988157391 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=5021, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 40859 and loc.getEndColumn() >= 40859
        ) or 
        (   // id=5022, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33734 and loc.getEndColumn() >= 33734
        ) or 
        (   // id=5023, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 60412 and loc.getEndColumn() >= 60412
        ) or 
        (   // id=5024, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 60422 and loc.getEndColumn() >= 60422
        ) or 
        (   // id=5025, type=WIN-TYPE-1, prop=core 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37155 and loc.getEndColumn() >= 37155
        ) or 
        (   // id=5026, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 70395 and loc.getEndColumn() >= 70395
        ) or 
        (   // id=5028, type=WIN-TYPE-1, prop=[object Object] 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 36916 and loc.getEndColumn() >= 36916
        ) or 
        (   // id=5030, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 433 and loc.getEndColumn() >= 433
        ) or 
        (   // id=5031, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 445 and loc.getEndColumn() >= 445
        ) or 
        (   // id=5032, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 462 and loc.getEndColumn() >= 462
        ) or 
        (   // id=5033, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 500 and loc.getEndColumn() >= 500
        ) or 
        (   // id=5034, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48192 and loc.getEndColumn() >= 48192
        ) or 
        (   // id=5036, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 45281 and loc.getEndColumn() >= 45281
        ) or 
        (   // id=5037, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 77152 and loc.getEndColumn() >= 77152
        ) or 
        (   // id=5038, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 77182 and loc.getEndColumn() >= 77182
        ) or 
        (   // id=5039, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37006 and loc.getEndColumn() >= 37006
        ) or 
        (   // id=5040, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57273 and loc.getEndColumn() >= 57273
        ) or 
        (   // id=5041, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57302 and loc.getEndColumn() >= 57302
        ) or 
        (   // id=5042, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57344 and loc.getEndColumn() >= 57344
        ) or 
        (   // id=5043, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37006 and loc.getEndColumn() >= 37006
        ) or 
        (   // id=5044, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57273 and loc.getEndColumn() >= 57273
        ) or 
        (   // id=5045, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57302 and loc.getEndColumn() >= 57302
        ) or 
        (   // id=5046, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57344 and loc.getEndColumn() >= 57344
        ) or 
        (   // id=5047, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=5048, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=5049, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=5050, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83169 and loc.getEndColumn() >= 83169
        ) or 
        (   // id=5051, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7322 and loc.getEndColumn() >= 7322
        ) or 
        (   // id=5052, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 20677 and loc.getEndColumn() >= 20677
        ) or 
        (   // id=5053, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 18455 and loc.getEndColumn() >= 18455
        ) or 
        (   // id=5054, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19883 and loc.getEndColumn() >= 19883
        ) or 
        (   // id=5055, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19941 and loc.getEndColumn() >= 19941
        ) or 
        (   // id=5056, type=WIN-TYPE-1, prop=__esModule 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84538 and loc.getEndColumn() >= 84538
        ) or 
        (   // id=5057, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84573 and loc.getEndColumn() >= 84573
        ) or 
        (   // id=5058, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84963 and loc.getEndColumn() >= 84963
        ) or 
        (   // id=5129, type=WIN-TYPE-1, prop=ga-disable-GTM-KLW9Z3 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 589 and loc.getEndLine() = 589 and
            loc.getStartColumn() <= 608 and loc.getEndColumn() >= 608
        ) or 
        (   // id=5173, type=WIN-TYPE-1, prop=webpackChunkhackmd_enterprise_edition 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 5121 and loc.getEndLine() = 5121 and
            loc.getStartColumn() <= 350 and loc.getEndColumn() >= 350
        ) or 
        (   // id=5174, type=WIN-TYPE-1, prop=webpackChunkhackmd_enterprise_edition 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 5121 and loc.getEndLine() = 5121 and
            loc.getStartColumn() <= 338 and loc.getEndColumn() >= 338
        ) or 
        (   // id=5175, type=WIN-TYPE-1, prop=TYPED_ARRAY_SUPPORT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 772 and loc.getEndLine() = 772 and
            loc.getStartColumn() <= 203 and loc.getEndColumn() >= 203
        ) or 
        (   // id=5179, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 767 and loc.getEndLine() = 767 and
            loc.getStartColumn() <= 9594 and loc.getEndColumn() >= 9594
        ) or 
        (   // id=5180, type=WIN-TYPE-1, prop=JS_SHA3_NO_WINDOW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 788 and loc.getEndLine() = 788 and
            loc.getStartColumn() <= 128 and loc.getEndColumn() >= 128
        ) or 
        (   // id=5181, type=WIN-TYPE-1, prop=JS_SHA3_NO_NODE_JS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 788 and loc.getEndLine() = 788 and
            loc.getStartColumn() <= 191 and loc.getEndColumn() >= 191
        ) or 
        (   // id=5182, type=WIN-TYPE-1, prop=JS_SHA3_NO_COMMON_JS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 788 and loc.getEndLine() = 788 and
            loc.getStartColumn() <= 288 and loc.getEndColumn() >= 288
        ) or 
        (   // id=5183, type=WIN-TYPE-1, prop=JS_SHA3_NO_ARRAY_BUFFER 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 788 and loc.getEndLine() = 788 and
            loc.getStartColumn() <= 340 and loc.getEndColumn() >= 340
        ) or 
        (   // id=5184, type=WIN-TYPE-1, prop=JS_SHA3_NO_NODE_JS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 788 and loc.getEndLine() = 788 and
            loc.getStartColumn() <= 1003 and loc.getEndColumn() >= 1003
        ) or 
        (   // id=5185, type=WIN-TYPE-1, prop=JS_SHA3_NO_ARRAY_BUFFER_IS_VIEW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 788 and loc.getEndLine() = 788 and
            loc.getStartColumn() <= 1137 and loc.getEndColumn() >= 1137
        ) or 
        (   // id=5186, type=WIN-TYPE-1, prop=_ethers 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 775 and loc.getEndLine() = 775 and
            loc.getStartColumn() <= 154311 and loc.getEndColumn() >= 154311
        ) or 
        (   // id=5187, type=WIN-TYPE-1, prop=_ethers 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 775 and loc.getEndLine() = 775 and
            loc.getStartColumn() <= 154336 and loc.getEndColumn() >= 154336
        ) or 
        (   // id=5188, type=WIN-TYPE-1, prop=ShadyCSS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 935 and loc.getEndLine() = 935 and
            loc.getStartColumn() <= 42 and loc.getEndColumn() >= 42
        ) or 
        (   // id=5189, type=WIN-TYPE-1, prop=reactiveElementPolyfillSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 939 and loc.getEndLine() = 939 and
            loc.getStartColumn() <= 189 and loc.getEndColumn() >= 189
        ) or 
        (   // id=5190, type=WIN-TYPE-1, prop=litPropertyMetadata 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 939 and loc.getEndLine() = 939 and
            loc.getStartColumn() <= 702 and loc.getEndColumn() >= 702
        ) or 
        (   // id=5191, type=WIN-TYPE-1, prop=litPropertyMetadata 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 939 and loc.getEndLine() = 939 and
            loc.getStartColumn() <= 745 and loc.getEndColumn() >= 745
        ) or 
        (   // id=5192, type=WIN-TYPE-1, prop=reactiveElementVersions 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 939 and loc.getEndLine() = 939 and
            loc.getStartColumn() <= 5818 and loc.getEndColumn() >= 5818
        ) or 
        (   // id=5193, type=WIN-TYPE-1, prop=reactiveElementVersions 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 939 and loc.getEndLine() = 939 and
            loc.getStartColumn() <= 5869 and loc.getEndColumn() >= 5869
        ) or 
        (   // id=5195, type=WIN-TYPE-1, prop=litHtmlPolyfillSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 945 and loc.getEndLine() = 945 and
            loc.getStartColumn() <= 6835 and loc.getEndColumn() >= 6835
        ) or 
        (   // id=5196, type=WIN-TYPE-1, prop=litHtmlVersions 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 945 and loc.getEndLine() = 945 and
            loc.getStartColumn() <= 6873 and loc.getEndColumn() >= 6873
        ) or 
        (   // id=5197, type=WIN-TYPE-1, prop=litHtmlVersions 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 945 and loc.getEndLine() = 945 and
            loc.getStartColumn() <= 6908 and loc.getEndColumn() >= 6908
        ) or 
        (   // id=5198, type=WIN-TYPE-1, prop=litElementHydrateSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 949 and loc.getEndLine() = 949 and
            loc.getStartColumn() <= 629 and loc.getEndColumn() >= 629
        ) or 
        (   // id=5199, type=WIN-TYPE-1, prop=litElementPolyfillSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 949 and loc.getEndLine() = 949 and
            loc.getStartColumn() <= 692 and loc.getEndColumn() >= 692
        ) or 
        (   // id=5200, type=WIN-TYPE-1, prop=litElementVersions 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 949 and loc.getEndLine() = 949 and
            loc.getStartColumn() <= 811 and loc.getEndColumn() >= 811
        ) or 
        (   // id=5201, type=WIN-TYPE-1, prop=litElementVersions 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 949 and loc.getEndLine() = 949 and
            loc.getStartColumn() <= 861 and loc.getEndColumn() >= 861
        ) or 
        (   // id=5202, type=WIN-TYPE-1, prop=ShadyCSS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 909 and loc.getEndLine() = 909 and
            loc.getStartColumn() <= 42 and loc.getEndColumn() >= 42
        ) or 
        (   // id=5203, type=WIN-TYPE-1, prop=reactiveElementPolyfillSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 913 and loc.getEndLine() = 913 and
            loc.getStartColumn() <= 189 and loc.getEndColumn() >= 189
        ) or 
        (   // id=5205, type=WIN-TYPE-1, prop=litHtmlPolyfillSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 919 and loc.getEndLine() = 919 and
            loc.getStartColumn() <= 6873 and loc.getEndColumn() >= 6873
        ) or 
        (   // id=5206, type=WIN-TYPE-1, prop=litElementHydrateSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 931 and loc.getEndLine() = 931 and
            loc.getStartColumn() <= 636 and loc.getEndColumn() >= 636
        ) or 
        (   // id=5207, type=WIN-TYPE-1, prop=litElementPolyfillSupport 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 931 and loc.getEndLine() = 931 and
            loc.getStartColumn() <= 698 and loc.getEndColumn() >= 698
        ) or 
        (   // id=5208, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 6465 and loc.getEndLine() = 6465 and
            loc.getStartColumn() <= 16606 and loc.getEndColumn() >= 16606
        ) or 
        (   // id=5209, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 6465 and loc.getEndLine() = 6465 and
            loc.getStartColumn() <= 16628 and loc.getEndColumn() >= 16628
        ) or 
        (   // id=5210, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 6465 and loc.getEndLine() = 6465 and
            loc.getStartColumn() <= 16643 and loc.getEndColumn() >= 16643
        ) or 
        (   // id=5211, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 6465 and loc.getEndLine() = 6465 and
            loc.getStartColumn() <= 16665 and loc.getEndColumn() >= 16665
        ) or 
        (   // id=5212, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 6465 and loc.getEndLine() = 6465 and
            loc.getStartColumn() <= 16681 and loc.getEndColumn() >= 16681
        ) or 
        (   // id=5213, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 6465 and loc.getEndLine() = 6465 and
            loc.getStartColumn() <= 16705 and loc.getEndColumn() >= 16705
        ) or 
        (   // id=5214, type=WIN-TYPE-1, prop=WALLET_CONNECT_PROJECT_ID 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 6474 and loc.getEndLine() = 6474 and
            loc.getStartColumn() <= 9162 and loc.getEndColumn() >= 9162
        ) or 
        (   // id=5219, type=WIN-TYPE-1, prop=ethereum 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 5122 and loc.getEndLine() = 5122 and
            loc.getStartColumn() <= 18894 and loc.getEndColumn() >= 18894
        ) or 
        (   // id=5330, type=WIN-TYPE-1, prop=closure_listenable_50185 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 410 and loc.getEndColumn() >= 410
        ) or 
        (   // id=5331, type=WIN-TYPE-1, prop=closure_lm_413048 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 63 and loc.getEndLine() = 63 and
            loc.getStartColumn() <= 142 and loc.getEndColumn() >= 142
        ) or 
        (   // id=5332, type=WIN-TYPE-1, prop=closure_lm_413048 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 98 and loc.getEndColumn() >= 98
        ) or 
        (   // id=5340, type=WIN-TYPE-1, prop=___grecaptcha_cfg 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 103 and loc.getEndColumn() >= 103
        ) or 
        (   // id=5341, type=WIN-TYPE-1, prop=___grecaptcha_cfg 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 101 and loc.getEndColumn() >= 101
        ) or 
        (   // id=5342, type=WIN-TYPE-1, prop=grecaptcha 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 153 and loc.getEndColumn() >= 153
        ) or 
        (   // id=5343, type=WIN-TYPE-1, prop=grecaptcha 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 151 and loc.getEndColumn() >= 151
        ) or 
        (   // id=5344, type=WIN-TYPE-1, prop=__recaptcha_api 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 267 and loc.getEndColumn() >= 267
        ) or 
        (   // id=5345, type=WIN-TYPE-1, prop=__google_recaptcha_client 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 507 and loc.getEndColumn() >= 507
        ) or 
        (   // id=5797, type=WIN-TYPE-1, prop=jQuery321069522259616426041 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=5963, type=WIN-TYPE-1, prop=jQuery321069522259616426042 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=7007, type=WIN-TYPE-1, prop=closure_listenable_80738 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 132 and loc.getEndLine() = 132 and
            loc.getStartColumn() <= 271 and loc.getEndColumn() >= 271
        ) or 
        (   // id=7008, type=WIN-TYPE-1, prop=closure_lm_933525 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 241 and loc.getEndLine() = 241 and
            loc.getStartColumn() <= 333 and loc.getEndColumn() >= 333
        ) or 
        (   // id=7009, type=WIN-TYPE-1, prop=closure_lm_933525 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 419 and loc.getEndLine() = 419 and
            loc.getStartColumn() <= 41 and loc.getEndColumn() >= 41
        ) or 
        (   // id=7884, type=WIN-TYPE-1, prop=onGoogleLibraryLoad 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 237 and loc.getEndLine() = 237 and
            loc.getStartColumn() <= 266 and loc.getEndColumn() >= 266
        ) or 
        (   // id=7887, type=WIN-TYPE-1, prop=domain 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 37 and loc.getEndLine() = 37 and
            loc.getStartColumn() <= 17 and loc.getEndColumn() >= 17
        ) or 
        (   // id=7888, type=WIN-TYPE-1, prop=urlpath 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 38 and loc.getEndLine() = 38 and
            loc.getStartColumn() <= 18 and loc.getEndColumn() >= 18
        ) or 
        (   // id=7889, type=WIN-TYPE-1, prop=debug 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=7890, type=WIN-TYPE-1, prop=version 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 40 and loc.getEndLine() = 40 and
            loc.getStartColumn() <= 18 and loc.getEndColumn() >= 18
        ) or 
        (   // id=7891, type=WIN-TYPE-1, prop=brand 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=7892, type=WIN-TYPE-1, prop=GOOGLE_API_KEY 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=7893, type=WIN-TYPE-1, prop=GOOGLE_CLIENT_ID 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 46 and loc.getEndLine() = 46 and
            loc.getStartColumn() <= 27 and loc.getEndColumn() >= 27
        ) or 
        (   // id=7894, type=WIN-TYPE-1, prop=DROPBOX_APP_KEY 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 47 and loc.getEndLine() = 47 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=7895, type=WIN-TYPE-1, prop=PLANTUML_SERVER 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 49 and loc.getEndLine() = 49 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=7896, type=WIN-TYPE-1, prop=ASSET_URL 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 51 and loc.getEndLine() = 51 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=7897, type=WIN-TYPE-1, prop=USER_CAN_CREATE_TEAM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=7898, type=WIN-TYPE-1, prop=USER_CAN_DELETE_ACCOUNT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 34 and loc.getEndColumn() >= 34
        ) or 
        (   // id=7899, type=WIN-TYPE-1, prop=USER_DELETE_ACCOUNT_VIA_EMAIL 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 55 and loc.getEndLine() = 55 and
            loc.getStartColumn() <= 40 and loc.getEndColumn() >= 40
        ) or 
        (   // id=7900, type=WIN-TYPE-1, prop=PAYMENT_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 56 and loc.getEndLine() = 56 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=7901, type=WIN-TYPE-1, prop=PAYMENT_PROMOTION_BANNER_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 57 and loc.getEndLine() = 57 and
            loc.getStartColumn() <= 43 and loc.getEndColumn() >= 43
        ) or 
        (   // id=7902, type=WIN-TYPE-1, prop=GITHUB_SYNC_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=7903, type=WIN-TYPE-1, prop=GITLAB_SYNC_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=7904, type=WIN-TYPE-1, prop=GITLAB_SYNC_BASE_URL 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=7905, type=WIN-TYPE-1, prop=VCS_SYNC_MODE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 61 and loc.getEndLine() = 61 and
            loc.getStartColumn() <= 24 and loc.getEndColumn() >= 24
        ) or 
        (   // id=7906, type=WIN-TYPE-1, prop=VCS_PROVIDER_NAME 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 62 and loc.getEndLine() = 62 and
            loc.getStartColumn() <= 28 and loc.getEndColumn() >= 28
        ) or 
        (   // id=7907, type=WIN-TYPE-1, prop=FREE_TEAM_NUM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 63 and loc.getEndLine() = 63 and
            loc.getStartColumn() <= 24 and loc.getEndColumn() >= 24
        ) or 
        (   // id=7908, type=WIN-TYPE-1, prop=FREE_TEAM_MEMBER_NUM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 64 and loc.getEndLine() = 64 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=7909, type=WIN-TYPE-1, prop=FREE_PUBLIC_TEAM_NUM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 65 and loc.getEndLine() = 65 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=7910, type=WIN-TYPE-1, prop=EE_SITE_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 67 and loc.getEndLine() = 67 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=7911, type=WIN-TYPE-1, prop=EE_SITE_NAME 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 68 and loc.getEndLine() = 68 and
            loc.getStartColumn() <= 23 and loc.getEndColumn() >= 23
        ) or 
        (   // id=7912, type=WIN-TYPE-1, prop=EE_SITE_LINK 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 69 and loc.getEndLine() = 69 and
            loc.getStartColumn() <= 23 and loc.getEndColumn() >= 23
        ) or 
        (   // id=7913, type=WIN-TYPE-1, prop=EESITE_INFO 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 70 and loc.getEndLine() = 70 and
            loc.getStartColumn() <= 22 and loc.getEndColumn() >= 22
        ) or 
        (   // id=7914, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 71 and loc.getEndLine() = 71 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=7915, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_TEAM 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=7916, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_NOTE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=7917, type=WIN-TYPE-1, prop=ENTERPRISE_DISCOVERY_VIEW_PERMISSION 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 74 and loc.getEndLine() = 74 and
            loc.getStartColumn() <= 47 and loc.getEndColumn() >= 47
        ) or 
        (   // id=7918, type=WIN-TYPE-1, prop=ALLOW_ANONYMOUS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 76 and loc.getEndLine() = 76 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=7919, type=WIN-TYPE-1, prop=ALLOW_ANONYMOUS_EDIT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 77 and loc.getEndLine() = 77 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=7920, type=WIN-TYPE-1, prop=PUBLIC_OVERVIEW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=7921, type=WIN-TYPE-1, prop=INTERNAL_PUBLIC_OVERVIEW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=7922, type=WIN-TYPE-1, prop=FULL_TEXT_SEARCH_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 34 and loc.getEndColumn() >= 34
        ) or 
        (   // id=7923, type=WIN-TYPE-1, prop=ALGOLIA_SEARCH_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 81 and loc.getEndLine() = 81 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=7924, type=WIN-TYPE-1, prop=MARKETING_EMAIL_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 82 and loc.getEndLine() = 82 and
            loc.getStartColumn() <= 33 and loc.getEndColumn() >= 33
        ) or 
        (   // id=7925, type=WIN-TYPE-1, prop=RECAPTCHA_SCORE_KEY 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 85 and loc.getEndLine() = 85 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=7926, type=WIN-TYPE-1, prop=WALLET_CONNECT_PROJECT_ID 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 89 and loc.getEndLine() = 89 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=7927, type=WIN-TYPE-1, prop=API_MANAGEMENT_UI_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 91 and loc.getEndLine() = 91 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=7928, type=WIN-TYPE-1, prop=FEEDBACK_UI_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 92 and loc.getEndLine() = 92 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=7929, type=WIN-TYPE-1, prop=PUBLISH_ENABLE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=7930, type=WIN-TYPE-1, prop=SHOW_HOT_NOTES 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=7931, type=WIN-TYPE-1, prop=HOT_NOTES_TIME_TYPE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 102 and loc.getEndLine() = 102 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=7932, type=WIN-TYPE-1, prop=SHOW_OVERVIEW 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 106 and loc.getEndLine() = 106 and
            loc.getStartColumn() <= 24 and loc.getEndColumn() >= 24
        ) or 
        (   // id=7933, type=WIN-TYPE-1, prop=TRASH_NOTE_DELETE_AFTER_FREE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 131 and loc.getEndLine() = 131 and
            loc.getStartColumn() <= 39 and loc.getEndColumn() >= 39
        ) or 
        (   // id=7934, type=WIN-TYPE-1, prop=TRASH_NOTE_DELETE_AFTER_PAID 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 132 and loc.getEndLine() = 132 and
            loc.getStartColumn() <= 39 and loc.getEndColumn() >= 39
        ) or 
        (   // id=7935, type=WIN-TYPE-1, prop=ENABLED_PREVIEW_FEATURE 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 135 and loc.getEndLine() = 135 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=7936, type=WIN-TYPE-1, prop=IMGUR_FALLBACK_CDN 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 141 and loc.getEndLine() = 141 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=7937, type=WIN-TYPE-1, prop=CLOUD_META_UI 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=7938, type=WIN-TYPE-1, prop=CLOUD_META_API 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 148 and loc.getEndLine() = 148 and
            loc.getStartColumn() <= 27 and loc.getEndColumn() >= 27
        ) or 
        (   // id=7939, type=WIN-TYPE-1, prop=CLOUD_META_MIGRATION 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 151 and loc.getEndLine() = 151 and
            loc.getStartColumn() <= 33 and loc.getEndColumn() >= 33
        ) or 
        (   // id=7940, type=WIN-TYPE-1, prop=YAML_METADATA_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 154 and loc.getEndLine() = 154 and
            loc.getStartColumn() <= 34 and loc.getEndColumn() >= 34
        ) or 
        (   // id=7941, type=WIN-TYPE-1, prop=NOTE_CAPACITY_LIMIT 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 158 and loc.getEndLine() = 158 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=7942, type=WIN-TYPE-1, prop=DOCUMENT_MAX_LENGTH 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 162 and loc.getEndLine() = 162 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=7943, type=WIN-TYPE-1, prop=SOCIAL_NETWORK_FEATURES_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 166 and loc.getEndLine() = 166 and
            loc.getStartColumn() <= 44 and loc.getEndColumn() >= 44
        ) or 
        (   // id=7944, type=WIN-TYPE-1, prop=PUBLISHMENT_MODERATION_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 170 and loc.getEndLine() = 170 and
            loc.getStartColumn() <= 43 and loc.getEndColumn() >= 43
        ) or 
        (   // id=7945, type=WIN-TYPE-1, prop=SUGGEST_EDIT_ENABLED 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 175 and loc.getEndLine() = 175 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=7946, type=WIN-TYPE-1, prop=REALTIME_CLIENT_WITH_CREDENTIALS 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 179 and loc.getEndLine() = 179 and
            loc.getStartColumn() <= 45 and loc.getEndColumn() >= 45
        ) or 
        (   // id=7947, type=WIN-TYPE-1, prop=dataLayer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 81 and loc.getEndColumn() >= 81
        ) or 
        (   // id=7948, type=WIN-TYPE-1, prop=dataLayer 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 79 and loc.getEndColumn() >= 79
        ) or 
        (   // id=7966, type=WIN-TYPE-1, prop=plausible 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 217 and loc.getEndLine() = 217 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=7967, type=WIN-TYPE-1, prop=plausible 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 217 and loc.getEndLine() = 217 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=8189, type=WIN-TYPE-1, prop=jQuery321039526152119619431 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=8347, type=WIN-TYPE-1, prop=jQuery321039526152119619432 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=9234, type=WIN-TYPE-1, prop=closure_listenable_654904 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 132 and loc.getEndLine() = 132 and
            loc.getStartColumn() <= 271 and loc.getEndColumn() >= 271
        ) or 
        (   // id=9235, type=WIN-TYPE-1, prop=closure_lm_653013 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 241 and loc.getEndLine() = 241 and
            loc.getStartColumn() <= 333 and loc.getEndColumn() >= 333
        ) or 
        (   // id=9236, type=WIN-TYPE-1, prop=closure_lm_653013 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 419 and loc.getEndLine() = 419 and
            loc.getStartColumn() <= 41 and loc.getEndColumn() >= 41
        ) or 
        (   // id=9272, type=WIN-TYPE-1, prop=closure_listenable_806575 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 410 and loc.getEndColumn() >= 410
        ) or 
        (   // id=9273, type=WIN-TYPE-1, prop=closure_lm_310688 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 63 and loc.getEndLine() = 63 and
            loc.getStartColumn() <= 142 and loc.getEndColumn() >= 142
        ) or 
        (   // id=9274, type=WIN-TYPE-1, prop=closure_lm_310688 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 98 and loc.getEndColumn() >= 98
        ) or 
        (   // id=9374, type=WIN-TYPE-1, prop=gaGlobal 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 82 and loc.getEndLine() = 82 and
            loc.getStartColumn() <= 323 and loc.getEndColumn() >= 323
        ) or 
        (   // id=9375, type=WIN-TYPE-1, prop=gaGlobal 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 82 and loc.getEndLine() = 82 and
            loc.getStartColumn() <= 320 and loc.getEndColumn() >= 320
        ) or 
        (   // id=10326, type=WIN-TYPE-1, prop=jQuery321062377691439972341 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=10484, type=WIN-TYPE-1, prop=jQuery321062377691439972342 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33470 and loc.getEndColumn() >= 33470
        ) or 
        (   // id=11545, type=WIN-TYPE-1, prop=closure_listenable_780314 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 132 and loc.getEndLine() = 132 and
            loc.getStartColumn() <= 271 and loc.getEndColumn() >= 271
        ) or 
        (   // id=11546, type=WIN-TYPE-1, prop=closure_lm_811361 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 241 and loc.getEndLine() = 241 and
            loc.getStartColumn() <= 333 and loc.getEndColumn() >= 333
        ) or 
        (   // id=11547, type=WIN-TYPE-1, prop=closure_lm_811361 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 419 and loc.getEndLine() = 419 and
            loc.getStartColumn() <= 41 and loc.getEndColumn() >= 41
        ) or 
        (   // id=11587, type=WIN-TYPE-1, prop=closure_listenable_387390 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 410 and loc.getEndColumn() >= 410
        ) or 
        (   // id=11588, type=WIN-TYPE-1, prop=closure_lm_281424 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 63 and loc.getEndLine() = 63 and
            loc.getStartColumn() <= 142 and loc.getEndColumn() >= 142
        ) or 
        (   // id=11589, type=WIN-TYPE-1, prop=closure_lm_281424 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 98 and loc.getEndColumn() >= 98
        )
        )
        ) and
        this = propRead
      )
    }
}
class IdentifiedClobberableSourceDocTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeOne() {
        exists(DataFlow::PropRead propRead |
            exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
        (   // id=171, type=DOC-TYPE-1, prop=createEventObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 363 and loc.getEndLine() = 363 and
            loc.getStartColumn() <= 396 and loc.getEndColumn() >= 396
        ) or 
        (   // id=331, type=DOC-TYPE-1, prop=createEventObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 524 and loc.getEndLine() = 524 and
            loc.getStartColumn() <= 412 and loc.getEndColumn() >= 412
        ) or 
        (   // id=333, type=DOC-TYPE-1, prop=createEventObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 247 and loc.getEndLine() = 247 and
            loc.getStartColumn() <= 204 and loc.getEndColumn() >= 204
        ) or 
        (   // id=336, type=DOC-TYPE-1, prop=createEventObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 318 and loc.getEndLine() = 318 and
            loc.getStartColumn() <= 187 and loc.getEndColumn() >= 187
        ) or 
        (   // id=419, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 70758 and loc.getEndColumn() >= 70758
        ) or 
        (   // id=434, type=DOC-TYPE-1, prop=jQuery321084623556594832671 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33469 and loc.getEndColumn() >= 33469
        ) or 
        (   // id=535, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 103 and loc.getEndLine() = 103 and
            loc.getStartColumn() <= 26485 and loc.getEndColumn() >= 26485
        ) or 
        (   // id=716, type=DOC-TYPE-1, prop=onajaxStart 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70652 and loc.getEndColumn() >= 70652
        ) or 
        (   // id=718, type=DOC-TYPE-1, prop=ajaxStart 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70851 and loc.getEndColumn() >= 70851
        ) or 
        (   // id=724, type=DOC-TYPE-1, prop=onajaxSend 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70652 and loc.getEndColumn() >= 70652
        ) or 
        (   // id=726, type=DOC-TYPE-1, prop=ajaxSend 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70851 and loc.getEndColumn() >= 70851
        ) or 
        (   // id=1006, type=DOC-TYPE-1, prop=parentWindow 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 276 and loc.getEndColumn() >= 276
        ) or 
        (   // id=1596, type=DOC-TYPE-1, prop=onajaxSuccess 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70652 and loc.getEndColumn() >= 70652
        ) or 
        (   // id=1598, type=DOC-TYPE-1, prop=ajaxSuccess 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70851 and loc.getEndColumn() >= 70851
        ) or 
        (   // id=1604, type=DOC-TYPE-1, prop=onajaxComplete 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70652 and loc.getEndColumn() >= 70652
        ) or 
        (   // id=1606, type=DOC-TYPE-1, prop=ajaxComplete 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70851 and loc.getEndColumn() >= 70851
        ) or 
        (   // id=1612, type=DOC-TYPE-1, prop=onajaxStop 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70652 and loc.getEndColumn() >= 70652
        ) or 
        (   // id=1614, type=DOC-TYPE-1, prop=ajaxStop 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70851 and loc.getEndColumn() >= 70851
        ) or 
        (   // id=1667, type=DOC-TYPE-1, prop=createEventObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 679 and loc.getEndLine() = 679 and
            loc.getStartColumn() <= 297 and loc.getEndColumn() >= 297
        ) or 
        (   // id=1668, type=DOC-TYPE-1, prop=createEventObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 457 and loc.getEndLine() = 457 and
            loc.getStartColumn() <= 187 and loc.getEndColumn() >= 187
        ) or 
        (   // id=1868, type=DOC-TYPE-1, prop=target 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/browser.sentry-cdn.com/5.15.5/bundle.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 51606 and loc.getEndColumn() >= 51606
        ) or 
        (   // id=1869, type=DOC-TYPE-1, prop=tagName 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/browser.sentry-cdn.com/5.15.5/bundle.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6721 and loc.getEndColumn() >= 6721
        ) or 
        (   // id=4976, type=DOC-TYPE-1, prop=jQuery321084437065988157391 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 33469 and loc.getEndColumn() >= 33469
        ) or 
        (   // id=6964, type=DOC-TYPE-1, prop=onfocusin 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 70652 and loc.getEndColumn() >= 70652
        ) or 
        (   // id=9188, type=DOC-TYPE-1, prop=createEventObject 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 524 and loc.getEndLine() = 524 and
            loc.getStartColumn() <= 297 and loc.getEndColumn() >= 297
        ) )
        ) and
        this = propRead
      )
  }
}
class IdentifiedClobberableSourceDocTypeTwo extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeTwo() {
        exists(DataFlow::PropRead propRead |
            exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
        (   // id=74, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 985 and loc.getEndColumn() >= 985
        ) or 
        (   // id=142, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 185 and loc.getEndColumn() >= 185
        ) or 
        (   // id=143, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 202 and loc.getEndColumn() >= 202
        ) or 
        (   // id=148, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 107 and loc.getEndColumn() >= 107
        ) or 
        (   // id=158, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 358 and loc.getEndLine() = 358 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=297, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 814 and loc.getEndLine() = 814 and
            loc.getStartColumn() <= 52 and loc.getEndColumn() >= 52
        ) or 
        (   // id=306, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 185 and loc.getEndColumn() >= 185
        ) or 
        (   // id=307, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 202 and loc.getEndColumn() >= 202
        ) or 
        (   // id=312, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 138 and loc.getEndLine() = 138 and
            loc.getStartColumn() <= 107 and loc.getEndColumn() >= 107
        ) or 
        (   // id=320, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 518 and loc.getEndLine() = 518 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=339, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/plausible.io/js/script.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 69 and loc.getEndColumn() >= 69
        ) or 
        (   // id=350, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 8739 and loc.getEndColumn() >= 8739
        ) or 
        (   // id=351, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 8766 and loc.getEndColumn() >= 8766
        ) or 
        (   // id=354, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 8594 and loc.getEndColumn() >= 8594
        ) or 
        (   // id=355, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/airtable.com/embed/app3QDBe2uMN3YObP/shrC8Ow2JkIIf1wzk.html") and
            loc.getStartLine() = 18 and loc.getEndLine() = 18 and
            loc.getStartColumn() <= 21 and loc.getEndColumn() >= 21
        ) or 
        (   // id=397, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 32845 and loc.getEndColumn() >= 32845
        ) or 
        (   // id=401, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 40160 and loc.getEndColumn() >= 40160
        ) or 
        (   // id=412, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 10091 and loc.getEndColumn() >= 10091
        ) or 
        (   // id=426, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 71538 and loc.getEndColumn() >= 71538
        ) or 
        (   // id=497, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-common.ca85b8e85b99563864b2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 41432 and loc.getEndColumn() >= 41432
        ) or 
        (   // id=540, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 44492 and loc.getEndColumn() >= 44492
        ) or 
        (   // id=567, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 10093 and loc.getEndColumn() >= 10093
        ) or 
        (   // id=639, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 13367 and loc.getEndColumn() >= 13367
        ) or 
        (   // id=676, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 260 and loc.getEndLine() = 260 and
            loc.getStartColumn() <= 80485 and loc.getEndColumn() >= 80485
        ) or 
        (   // id=687, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6565 and loc.getEndColumn() >= 6565
        ) or 
        (   // id=740, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 225 and loc.getEndLine() = 225 and
            loc.getStartColumn() <= 8657 and loc.getEndColumn() >= 8657
        ) or 
        (   // id=741, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 225 and loc.getEndLine() = 225 and
            loc.getStartColumn() <= 8677 and loc.getEndColumn() >= 8677
        ) or 
        (   // id=762, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 187 and loc.getEndLine() = 187 and
            loc.getStartColumn() <= 10791 and loc.getEndColumn() >= 10791
        ) or 
        (   // id=763, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 187 and loc.getEndLine() = 187 and
            loc.getStartColumn() <= 10817 and loc.getEndColumn() >= 10817
        ) or 
        (   // id=764, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 187 and loc.getEndLine() = 187 and
            loc.getStartColumn() <= 10849 and loc.getEndColumn() >= 10849
        ) or 
        (   // id=816, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11828 and loc.getEndColumn() >= 11828
        ) or 
        (   // id=1002, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 472 and loc.getEndLine() = 472 and
            loc.getStartColumn() <= 424 and loc.getEndColumn() >= 424
        ) or 
        (   // id=1004, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 177 and loc.getEndColumn() >= 177
        ) or 
        (   // id=1005, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 196 and loc.getEndColumn() >= 196
        ) or 
        (   // id=1570, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 510 and loc.getEndLine() = 510 and
            loc.getStartColumn() <= 165 and loc.getEndColumn() >= 165
        ) or 
        (   // id=1571, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 510 and loc.getEndLine() = 510 and
            loc.getStartColumn() <= 321 and loc.getEndColumn() >= 321
        ) or 
        (   // id=1647, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 173 and loc.getEndLine() = 173 and
            loc.getStartColumn() <= 185 and loc.getEndColumn() >= 185
        ) or 
        (   // id=1648, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 173 and loc.getEndLine() = 173 and
            loc.getStartColumn() <= 202 and loc.getEndColumn() >= 202
        ) or 
        (   // id=1653, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 107 and loc.getEndColumn() >= 107
        ) or 
        (   // id=1661, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 673 and loc.getEndLine() = 673 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=1673, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 539 and loc.getEndLine() = 539 and
            loc.getStartColumn() <= 321 and loc.getEndColumn() >= 321
        ) or 
        (   // id=1680, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 589 and loc.getEndLine() = 589 and
            loc.getStartColumn() <= 534 and loc.getEndColumn() >= 534
        ) or 
        (   // id=1786, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 328 and loc.getEndLine() = 328 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=1791, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 328 and loc.getEndLine() = 328 and
            loc.getStartColumn() <= 8590 and loc.getEndColumn() >= 8590
        ) or 
        (   // id=1792, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 328 and loc.getEndLine() = 328 and
            loc.getStartColumn() <= 8648 and loc.getEndColumn() >= 8648
        ) or 
        (   // id=1793, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 397 and loc.getEndColumn() >= 397
        ) or 
        (   // id=1794, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 420 and loc.getEndColumn() >= 420
        ) or 
        (   // id=1802, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 83 and loc.getEndLine() = 83 and
            loc.getStartColumn() <= 275 and loc.getEndColumn() >= 275
        ) or 
        (   // id=1803, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 83 and loc.getEndLine() = 83 and
            loc.getStartColumn() <= 302 and loc.getEndColumn() >= 302
        ) or 
        (   // id=1825, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 569 and loc.getEndColumn() >= 569
        ) or 
        (   // id=1918, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 415 and loc.getEndLine() = 415 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=1919, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 415 and loc.getEndLine() = 415 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=1922, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 537 and loc.getEndLine() = 537 and
            loc.getStartColumn() <= 313 and loc.getEndColumn() >= 313
        ) or 
        (   // id=1923, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 537 and loc.getEndLine() = 537 and
            loc.getStartColumn() <= 333 and loc.getEndColumn() >= 333
        ) or 
        (   // id=1949, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/tracks.hackmd.io/js/script.manual.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 69 and loc.getEndColumn() >= 69
        ) or 
        (   // id=1963, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 809 and loc.getEndLine() = 809 and
            loc.getStartColumn() <= 289 and loc.getEndColumn() >= 289
        ) or 
        (   // id=2184, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 51051 and loc.getEndColumn() >= 51051
        ) or 
        (   // id=2190, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 19224 and loc.getEndColumn() >= 19224
        ) or 
        (   // id=2191, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 19240 and loc.getEndColumn() >= 19240
        ) or 
        (   // id=2237, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 28339 and loc.getEndColumn() >= 28339
        ) or 
        (   // id=2240, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 28646 and loc.getEndColumn() >= 28646
        ) or 
        (   // id=2248, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 39422 and loc.getEndColumn() >= 39422
        ) or 
        (   // id=2270, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 27158 and loc.getEndColumn() >= 27158
        ) or 
        (   // id=3117, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 24998 and loc.getEndColumn() >= 24998
        ) or 
        (   // id=3118, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25442 and loc.getEndColumn() >= 25442
        ) or 
        (   // id=5027, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth-common.7665eb044d55775ae1c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 41432 and loc.getEndColumn() >= 41432
        ) or 
        (   // id=5177, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 5121 and loc.getEndLine() = 5121 and
            loc.getStartColumn() <= 4078 and loc.getEndColumn() >= 4078
        ) or 
        (   // id=5218, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 5120 and loc.getEndLine() = 5120 and
            loc.getStartColumn() <= 45639 and loc.getEndColumn() >= 45639
        ) or 
        (   // id=5348, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 952 and loc.getEndColumn() >= 952
        ))
        ) and
        this = propRead
      )
  }
}
class IdentifiedClobberableSourceDOMAPI extends DataFlow::Node {
    IdentifiedClobberableSourceDOMAPI() {
        exists(DataFlow::PropRead propRead |
            exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
        (   // id=64, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 189 and loc.getEndLine() = 189 and
            loc.getStartColumn() <= 47 and loc.getEndColumn() >= 47
        ) or 
        (   // id=76, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1218 and loc.getEndColumn() >= 1218
        ) or 
        (   // id=79, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1334 and loc.getEndColumn() >= 1334
        ) or 
        (   // id=84, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 405 and loc.getEndLine() = 405 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=87, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 405 and loc.getEndLine() = 405 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=88, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 819 and loc.getEndLine() = 819 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=91, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 819 and loc.getEndLine() = 819 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=93, type=DOM-API, prop=.home-container .price-info-container, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 844 and loc.getEndLine() = 844 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=94, type=DOM-API, prop=.home-container .price-info-container, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 844 and loc.getEndLine() = 844 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=96, type=DOM-API, prop=cycle-toggle-cb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 845 and loc.getEndLine() = 845 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=98, type=DOM-API, prop=cycle-toggle-cb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 845 and loc.getEndLine() = 845 and
            loc.getStartColumn() <= 60 and loc.getEndColumn() >= 60
        ) or 
        (   // id=102, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 975 and loc.getEndLine() = 975 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=105, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 975 and loc.getEndLine() = 975 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=106, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1069 and loc.getEndLine() = 1069 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=109, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1069 and loc.getEndLine() = 1069 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=110, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1081 and loc.getEndLine() = 1081 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=113, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1081 and loc.getEndLine() = 1081 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=115, type=DOM-API, prop=signin-form, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1250 and loc.getEndLine() = 1250 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=116, type=DOM-API, prop=#signin-form input[type="submit"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1250 and loc.getEndLine() = 1250 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=117, type=DOM-API, prop=#signin-form input[type="submit"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1250 and loc.getEndLine() = 1250 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=118, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1282 and loc.getEndLine() = 1282 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=119, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1294 and loc.getEndLine() = 1294 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=122, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1294 and loc.getEndLine() = 1294 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=123, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1360 and loc.getEndLine() = 1360 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=126, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1360 and loc.getEndLine() = 1360 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=127, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1365 and loc.getEndLine() = 1365 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=130, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1365 and loc.getEndLine() = 1365 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=131, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1373 and loc.getEndLine() = 1373 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=134, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1373 and loc.getEndLine() = 1373 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=136, type=DOM-API, prop=.ui-view-email-address, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1523 and loc.getEndLine() = 1523 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=137, type=DOM-API, prop=.ui-view-email-address, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1523 and loc.getEndLine() = 1523 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=139, type=DOM-API, prop=announcement, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1551 and loc.getEndLine() = 1551 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=146, type=DOM-API, prop=:root, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=147, type=DOM-API, prop=:root, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=176, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 56 and loc.getEndLine() = 56 and
            loc.getStartColumn() <= 380 and loc.getEndColumn() >= 380
        ) or 
        (   // id=179, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 57 and loc.getEndLine() = 57 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=310, type=DOM-API, prop=:root, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 138 and loc.getEndLine() = 138 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=311, type=DOM-API, prop=:root, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 138 and loc.getEndLine() = 138 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=359, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 9095 and loc.getEndColumn() >= 9095
        ) or 
        (   // id=365, type=DOM-API, prop=sizzle1713545964522, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 9270 and loc.getEndColumn() >= 9270
        ) or 
        (   // id=368, type=DOM-API, prop=[msallowcapture^=''], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10564 and loc.getEndColumn() >= 10564
        ) or 
        (   // id=369, type=DOM-API, prop=[msallowcapture^=''], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10564 and loc.getEndColumn() >= 10564
        ) or 
        (   // id=370, type=DOM-API, prop=[selected], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10649 and loc.getEndColumn() >= 10649
        ) or 
        (   // id=371, type=DOM-API, prop=[selected], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10649 and loc.getEndColumn() >= 10649
        ) or 
        (   // id=372, type=DOM-API, prop=[id~=sizzle1713545964522-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=373, type=DOM-API, prop=[id~=sizzle1713545964522-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=374, type=DOM-API, prop=:checked, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10786 and loc.getEndColumn() >= 10786
        ) or 
        (   // id=375, type=DOM-API, prop=:checked, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10786 and loc.getEndColumn() >= 10786
        ) or 
        (   // id=376, type=DOM-API, prop=sizzle1713545964522, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=377, type=DOM-API, prop=a#sizzle1713545964522+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=378, type=DOM-API, prop=a#sizzle1713545964522+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=381, type=DOM-API, prop=[name=d], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11124 and loc.getEndColumn() >= 11124
        ) or 
        (   // id=382, type=DOM-API, prop=[name=d], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11124 and loc.getEndColumn() >= 11124
        ) or 
        (   // id=383, type=DOM-API, prop=:enabled, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11196 and loc.getEndColumn() >= 11196
        ) or 
        (   // id=384, type=DOM-API, prop=:enabled, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11196 and loc.getEndColumn() >= 11196
        ) or 
        (   // id=385, type=DOM-API, prop=:disabled, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11301 and loc.getEndColumn() >= 11301
        ) or 
        (   // id=386, type=DOM-API, prop=:disabled, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11301 and loc.getEndColumn() >= 11301
        ) or 
        (   // id=387, type=DOM-API, prop=*,:x, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 11377 and loc.getEndColumn() >= 11377
        ) or 
        (   // id=421, type=DOM-API, prop=span, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 70907 and loc.getEndColumn() >= 70907
        ) or 
        (   // id=484, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover-vendor.af717da25948e2213a85.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 70412 and loc.getEndColumn() >= 70412
        ) or 
        (   // id=541, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 44509 and loc.getEndColumn() >= 44509
        ) or 
        (   // id=549, type=DOM-API, prop=[data-i18n], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=550, type=DOM-API, prop=[data-i18n], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=556, type=DOM-API, prop=meta[name=csrf-token], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=557, type=DOM-API, prop=meta[name=csrf-token], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=578, type=DOM-API, prop=createTeamModal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=583, type=DOM-API, prop=createTeamModal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=584, type=DOM-API, prop=#createTeamModal .alert, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=585, type=DOM-API, prop=#createTeamModal .alert, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=593, type=DOM-API, prop=ui-locale, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=598, type=DOM-API, prop=.ui-locale option, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=599, type=DOM-API, prop=.ui-locale option, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=604, type=DOM-API, prop=select.ui-locale option[value="en"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=605, type=DOM-API, prop=select.ui-locale option[value="en"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=620, type=DOM-API, prop=ui-signout, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=626, type=DOM-API, prop=header-wrapper, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=645, type=DOM-API, prop=btn-hide-show, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=651, type=DOM-API, prop=plans-comparison-table, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=656, type=DOM-API, prop=.hackmd-navbar .ui-navbar-toggle, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=657, type=DOM-API, prop=.hackmd-navbar .ui-navbar-toggle, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=660, type=DOM-API, prop=.navbar-header .dropdown, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=661, type=DOM-API, prop=.navbar-header .dropdown, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=671, type=DOM-API, prop=header.header-wrapper, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=672, type=DOM-API, prop=header.header-wrapper, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=673, type=DOM-API, prop=site-content, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=675, type=DOM-API, prop=hackmd-navbar, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=677, type=DOM-API, prop=[data-toggle=sidenav], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=678, type=DOM-API, prop=[data-toggle=sidenav], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=679, type=DOM-API, prop=.home-container .carousel-item, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=680, type=DOM-API, prop=.home-container .carousel-item, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=683, type=DOM-API, prop=home, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=684, type=DOM-API, prop=#home .carousel, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=685, type=DOM-API, prop=#home .carousel, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=686, type=DOM-API, prop=carousel-indicators, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=698, type=DOM-API, prop=a[href="#"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=699, type=DOM-API, prop=a[href="#"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=727, type=DOM-API, prop=ui-signin-action, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=728, type=DOM-API, prop=new-note-menu, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=730, type=DOM-API, prop=hover-dropdown, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=732, type=DOM-API, prop=#createTeamModal button[type="submit"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=733, type=DOM-API, prop=#createTeamModal button[type="submit"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=734, type=DOM-API, prop=.announcement .ui-close, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=735, type=DOM-API, prop=.announcement .ui-close, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=736, type=DOM-API, prop=ui-announcement-close, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=737, type=DOM-API, prop=announcement-trigger, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=738, type=DOM-API, prop=announcement-label, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=744, type=DOM-API, prop=recent, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=745, type=DOM-API, prop=settings, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=748, type=DOM-API, prop=hmd-submenu-portal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 29 and loc.getEndLine() = 29 and
            loc.getStartColumn() <= 28068 and loc.getEndColumn() >= 28068
        ) or 
        (   // id=750, type=DOM-API, prop=hackmd-app, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 29 and loc.getEndLine() = 29 and
            loc.getStartColumn() <= 28118 and loc.getEndColumn() >= 28118
        ) or 
        (   // id=770, type=DOM-API, prop=profile, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=774, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6765 and loc.getEndColumn() >= 6765
        ) or 
        (   // id=777, type=DOM-API, prop=loading-modal, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=797, type=DOM-API, prop=feedback-modal, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=798, type=DOM-API, prop=alert-danger, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=799, type=DOM-API, prop=ui-feedback-submit, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=800, type=DOM-API, prop=sizzle1713545964522, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=801, type=DOM-API, prop=#sizzle1713545964522 input[type="checkbox"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=802, type=DOM-API, prop=#sizzle1713545964522 input[type="checkbox"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=804, type=DOM-API, prop=#sizzle1713545964522 input[name="email"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=805, type=DOM-API, prop=#sizzle1713545964522 input[name="email"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=807, type=DOM-API, prop=#sizzle1713545964522 textarea[name="feedback"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=808, type=DOM-API, prop=#sizzle1713545964522 textarea[name="feedback"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=809, type=DOM-API, prop=rating-group, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=810, type=DOM-API, prop=feedback-success-modal, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=811, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 38837 and loc.getEndColumn() >= 38837
        ) or 
        (   // id=817, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 38837 and loc.getEndColumn() >= 38837
        ) or 
        (   // id=899, type=DOM-API, prop=team-manage-app, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 29 and loc.getEndLine() = 29 and
            loc.getStartColumn() <= 23811 and loc.getEndColumn() >= 23811
        ) or 
        (   // id=903, type=DOM-API, prop=ui-spinner, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=904, type=DOM-API, prop=ui-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=905, type=DOM-API, prop=ui-short-status, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=906, type=DOM-API, prop=ui-status, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=907, type=DOM-API, prop=ui-new, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=908, type=DOM-API, prop=ui-extra-revision, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=909, type=DOM-API, prop=ui-download-markdown, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=910, type=DOM-API, prop=ui-download-html, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=911, type=DOM-API, prop=ui-download-raw-html, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=912, type=DOM-API, prop=ui-download-pdf-beta, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=913, type=DOM-API, prop=ui-save-dropbox, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=914, type=DOM-API, prop=ui-save-google-drive, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=915, type=DOM-API, prop=ui-save-gist, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=916, type=DOM-API, prop=ui-save-snippet, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=917, type=DOM-API, prop=ui-import-dropbox, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=918, type=DOM-API, prop=ui-import-google-drive, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=919, type=DOM-API, prop=ui-import-gist, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=920, type=DOM-API, prop=ui-import-snippet, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=921, type=DOM-API, prop=ui-import-clipboard, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=922, type=DOM-API, prop=ui-template-insert, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=923, type=DOM-API, prop=ui-template-save, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=924, type=DOM-API, prop=ui-new-with-template, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=925, type=DOM-API, prop=ui-mode, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=926, type=DOM-API, prop=ui-edit, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=927, type=DOM-API, prop=ui-view, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=928, type=DOM-API, prop=ui-both, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=929, type=DOM-API, prop=ui-upload-image, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=930, type=DOM-API, prop=ui-infobar, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=931, type=DOM-API, prop=ui-lastchange, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=932, type=DOM-API, prop=ui-lastchangeuser, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=933, type=DOM-API, prop=ui-no-lastchangeuser, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=934, type=DOM-API, prop=ui-notification, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=935, type=DOM-API, prop=ui-notification-status, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=936, type=DOM-API, prop=ui-notification-subscribe, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=937, type=DOM-API, prop=ui-notification-unsubscribe, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=938, type=DOM-API, prop=ui-notification-watch, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=939, type=DOM-API, prop=ui-notification-mention, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=940, type=DOM-API, prop=ui-notification-never, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=941, type=DOM-API, prop=ui-permission, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=942, type=DOM-API, prop=ui-permission-label, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=943, type=DOM-API, prop=ui-permission-freely, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=944, type=DOM-API, prop=ui-permission-editable, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=945, type=DOM-API, prop=ui-permission-locked, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=946, type=DOM-API, prop=ui-permission-private, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=947, type=DOM-API, prop=ui-permission-limited, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=948, type=DOM-API, prop=ui-permission-protected, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=949, type=DOM-API, prop=public-published-toggle, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=950, type=DOM-API, prop=public-publish-container, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=951, type=DOM-API, prop=ui-published-note, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=952, type=DOM-API, prop=fill-username-banner, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=953, type=DOM-API, prop=ui-transfer-note, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=954, type=DOM-API, prop=ui-delete-note, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=955, type=DOM-API, prop=ui-toc, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=956, type=DOM-API, prop=ui-affix-toc, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=957, type=DOM-API, prop=ui-toc-label, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=958, type=DOM-API, prop=ui-toc-dropdown, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=959, type=DOM-API, prop=ui-edit-area, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=960, type=DOM-API, prop=ui-view-area, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=961, type=DOM-API, prop=.ui-edit-area .CodeMirror, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=962, type=DOM-API, prop=.ui-edit-area .CodeMirror, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=963, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-scroll, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=964, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-scroll, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=965, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-sizer, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=966, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-sizer, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=967, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-sizer > div, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=968, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-sizer > div, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=969, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-lines, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=970, type=DOM-API, prop=.ui-edit-area .CodeMirror .CodeMirror-lines, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=971, type=DOM-API, prop=.ui-view-area .markdown-body, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=972, type=DOM-API, prop=.ui-view-area .markdown-body, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=973, type=DOM-API, prop=ui-resizable-handle, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=974, type=DOM-API, prop=ui-sync-toggle, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=975, type=DOM-API, prop=snippetImportModalProjects, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=976, type=DOM-API, prop=snippetImportModalSnippets, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=977, type=DOM-API, prop=namedRevisionModal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=978, type=DOM-API, prop=create-template-modal, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=979, type=DOM-API, prop=templateModal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=980, type=DOM-API, prop=githubChangesModal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=981, type=DOM-API, prop=pushChangesModal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=983, type=DOM-API, prop=githubSyncPullModal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 26254 and loc.getEndColumn() >= 26254
        ) or 
        (   // id=984, type=DOM-API, prop=ui-template-spinner, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=985, type=DOM-API, prop=ui-template-filter-all, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=986, type=DOM-API, prop=ui-template-filter-default, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=987, type=DOM-API, prop=ui-template-filter-personal, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=988, type=DOM-API, prop=ui-template-filter-team, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=989, type=DOM-API, prop=ui-template-filter-shared, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=990, type=DOM-API, prop=ui-template-list-filter, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=992, type=DOM-API, prop=ui-create-template-btn, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=993, type=DOM-API, prop=ui-use-template-btn, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=994, type=DOM-API, prop=ui-use-template-btn-mobile, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=995, type=DOM-API, prop=ui-template-cancel, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=996, type=DOM-API, prop=ui-create-template-modal-confirm, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=997, type=DOM-API, prop=ui-delete-template-modal-confirm, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=998, type=DOM-API, prop=delete-template-modal, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1014, type=DOM-API, prop=.grecaptcha-badge, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 179 and loc.getEndLine() = 179 and
            loc.getStartColumn() <= 59 and loc.getEndColumn() >= 59
        ) or 
        (   // id=1015, type=DOM-API, prop=.grecaptcha-badge, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 179 and loc.getEndLine() = 179 and
            loc.getStartColumn() <= 59 and loc.getEndColumn() >= 59
        ) or 
        (   // id=1021, type=DOM-API, prop=TEXTAREA, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 345 and loc.getEndLine() = 345 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=1033, type=DOM-API, prop=.g-recaptcha, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 179 and loc.getEndLine() = 179 and
            loc.getStartColumn() <= 59 and loc.getEndColumn() >= 59
        ) or 
        (   // id=1034, type=DOM-API, prop=.g-recaptcha, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 179 and loc.getEndLine() = 179 and
            loc.getStartColumn() <= 59 and loc.getEndColumn() >= 59
        ) or 
        (   // id=1035, type=DOM-API, prop=Non-Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1036, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1037, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1038, type=DOM-API, prop=cycle-toggle-cb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1039, type=DOM-API, prop=templateName, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1041, type=DOM-API, prop=save-template-directly, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1042, type=DOM-API, prop=save-template-as-another-template, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1043, type=DOM-API, prop=deleteNoteCheck, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1044, type=DOM-API, prop=email, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1045, type=DOM-API, prop=inputEmail, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1046, type=DOM-API, prop=password, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1047, type=DOM-API, prop=inputPassword, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1048, type=DOM-API, prop=team-name, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1049, type=DOM-API, prop=team-description, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1050, type=DOM-API, prop=team-path, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1051, type=DOM-API, prop=input, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1052, type=DOM-API, prop=button, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1086, type=DOM-API, prop=template-name, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1136, type=DOM-API, prop=helpId, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1188, type=DOM-API, prop=input[type="password"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1585, type=DOM-API, prop=ui-signin, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1586, type=DOM-API, prop=ui-or, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1587, type=DOM-API, prop=ui-welcome, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1588, type=DOM-API, prop=ui-avatar, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1589, type=DOM-API, prop=ui-name, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1651, type=DOM-API, prop=:root, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=1652, type=DOM-API, prop=:root, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=1684, type=DOM-API, prop=__gaOptOutExtension, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 589 and loc.getEndLine() = 589 and
            loc.getStartColumn() <= 824 and loc.getEndColumn() >= 824
        ) or 
        (   // id=1773, type=DOM-API, prop=.g_id_signout, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 146 and loc.getEndLine() = 146 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=1774, type=DOM-API, prop=.g_id_signout, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 146 and loc.getEndLine() = 146 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=1776, type=DOM-API, prop=g_id_onload, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 179 and loc.getEndColumn() >= 179
        ) or 
        (   // id=1780, type=DOM-API, prop=.g_id_signin, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 146 and loc.getEndLine() = 146 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=1781, type=DOM-API, prop=.g_id_signin, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 146 and loc.getEndLine() = 146 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=1788, type=DOM-API, prop=googleidentityservice_button_styles, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/accounts.google.com/gsi/client.html") and
            loc.getStartLine() = 328 and loc.getEndLine() = 328 and
            loc.getStartColumn() <= 8436 and loc.getEndColumn() >= 8436
        ) or 
        (   // id=1829, type=DOM-API, prop=__gaOptOutExtension, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google-analytics.com/analytics.js") and
            loc.getStartLine() = 27 and loc.getEndLine() = 27 and
            loc.getStartColumn() <= 53 and loc.getEndColumn() >= 53
        ) or 
        (   // id=1864, type=DOM-API, prop=.ui-guest-signin-tooltip:visible, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=1867, type=DOM-API, prop=ui-guest-signin-tooltip, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10339 and loc.getEndColumn() >= 10339
        ) or 
        (   // id=1879, type=DOM-API, prop=overview-page, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 260 and loc.getEndLine() = 260 and
            loc.getStartColumn() <= 74781 and loc.getEndColumn() >= 74781
        ) or 
        (   // id=1881, type=DOM-API, prop=back-to-top, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1901, type=DOM-API, prop=[data-toggle="tooltip"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=1902, type=DOM-API, prop=[data-toggle="tooltip"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=1905, type=DOM-API, prop=header, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/cover.5b098454aefa004fc063.js") and
            loc.getStartLine() = 260 and loc.getEndLine() = 260 and
            loc.getStartColumn() <= 81916 and loc.getEndColumn() >= 81916
        ) or 
        (   // id=1907, type=DOM-API, prop=announcement, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1908, type=DOM-API, prop=announcement-popover, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1909, type=DOM-API, prop=#carouselFirstIndicators .next,#carouselFirstIndicators .prev, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=1910, type=DOM-API, prop=#carouselFirstIndicators .next,#carouselFirstIndicators .prev, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=1925, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 555 and loc.getEndLine() = 555 and
            loc.getStartColumn() <= 244 and loc.getEndColumn() >= 244
        ) or 
        (   // id=1927, type=DOM-API, prop=iframe, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtag/js.html") and
            loc.getStartLine() = 555 and loc.getEndLine() = 555 and
            loc.getStartColumn() <= 393 and loc.getEndColumn() >= 393
        ) or 
        (   // id=1933, type=DOM-API, prop=btn-fixed-bottom, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=1946, type=DOM-API, prop=Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 505 and loc.getEndLine() = 505 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=1947, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 505 and loc.getEndLine() = 505 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=1954, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/tag/b1dcrbrq8f.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 321 and loc.getEndColumn() >= 321
        ) or 
        (   // id=1961, type=DOM-API, prop=:hover, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 154 and loc.getEndColumn() >= 154
        ) or 
        (   // id=1962, type=DOM-API, prop=:hover, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.gstatic.com/recaptcha/releases/rz4DvU-cY2JYCwHSTck0_qm-/recaptcha__en.js") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 154 and loc.getEndColumn() >= 154
        ) or 
        (   // id=1973, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1974, type=DOM-API, prop=spin, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=2127, type=DOM-API, prop=#carouselSecondIndicators .next,#carouselSecondIndicators .prev, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2128, type=DOM-API, prop=#carouselSecondIndicators .next,#carouselSecondIndicators .prev, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2130, type=DOM-API, prop=carouselSecondIndicators, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2131, type=DOM-API, prop=#carouselSecondIndicators .item.active, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2132, type=DOM-API, prop=#carouselSecondIndicators .item.active, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2596, type=DOM-API, prop=carouselFirstIndicators, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2597, type=DOM-API, prop=#carouselFirstIndicators .item.active, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2598, type=DOM-API, prop=#carouselFirstIndicators .item.active, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=2604, type=DOM-API, prop=active, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=2998, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=3088, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 269 and loc.getEndColumn() >= 269
        ) or 
        (   // id=3091, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.googletagmanager.com/gtm.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 426 and loc.getEndColumn() >= 426
        ) or 
        (   // id=3125, type=DOM-API, prop=[data-toggle="popover"]:not(.manual), api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=3126, type=DOM-API, prop=[data-toggle="popover"]:not(.manual), api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=3131, type=DOM-API, prop=dropdown-backdrop, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=3134, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10037 and loc.getEndColumn() >= 10037
        ) or 
        (   // id=4233, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.clarity.ms/s/0.7.31/clarity.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 29524 and loc.getEndColumn() >= 29524
        ) or 
        (   // id=4719, type=DOM-API, prop=___gatsby, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4720, type=DOM-API, prop=react-root, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4724, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 36 and loc.getEndLine() = 36 and
            loc.getStartColumn() <= 47 and loc.getEndColumn() >= 47
        ) or 
        (   // id=4782, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 189 and loc.getEndLine() = 189 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4787, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 189 and loc.getEndLine() = 189 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4788, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 205 and loc.getEndLine() = 205 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4793, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 205 and loc.getEndLine() = 205 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4794, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 220 and loc.getEndLine() = 220 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4797, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 220 and loc.getEndLine() = 220 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4880, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 376 and loc.getEndLine() = 376 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4907, type=DOM-API, prop=sizzle1713545992133, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 9270 and loc.getEndColumn() >= 9270
        ) or 
        (   // id=4914, type=DOM-API, prop=[id~=sizzle1713545992133-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=4915, type=DOM-API, prop=[id~=sizzle1713545992133-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=4918, type=DOM-API, prop=sizzle1713545992133, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=4919, type=DOM-API, prop=a#sizzle1713545992133+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=4920, type=DOM-API, prop=a#sizzle1713545992133+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=5171, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5178, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 5121 and loc.getEndLine() = 5121 and
            loc.getStartColumn() <= 4095 and loc.getEndColumn() >= 4095
        ) or 
        (   // id=5216, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/auth.ec97e283bf37d35e0f5b.js") and
            loc.getStartLine() = 5120 and loc.getEndLine() = 5120 and
            loc.getStartColumn() <= 45030 and loc.getEndColumn() >= 45030
        ) or 
        (   // id=5222, type=DOM-API, prop=[data-inline-form="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=5223, type=DOM-API, prop=[data-inline-form="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=5224, type=DOM-API, prop=btn-web3, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=5225, type=DOM-API, prop=ui-disconnect-connected-wallets, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 6877 and loc.getEndColumn() >= 6877
        ) or 
        (   // id=5226, type=DOM-API, prop=Non-Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5227, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5228, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5229, type=DOM-API, prop=inputUsername, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5231, type=DOM-API, prop=inputEmail, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5233, type=DOM-API, prop=inputPassword, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5235, type=DOM-API, prop=input, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5236, type=DOM-API, prop=button, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5246, type=DOM-API, prop=input[type="password"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/join.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5350, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1185 and loc.getEndColumn() >= 1185
        ) or 
        (   // id=5353, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/www.google.com/recaptcha/enterprise.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1301 and loc.getEndColumn() >= 1301
        ) or 
        (   // id=5443, type=DOM-API, prop=Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5531, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 446 and loc.getEndLine() = 446 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5532, type=DOM-API, prop=spin, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 446 and loc.getEndLine() = 446 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5538, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 521 and loc.getEndLine() = 521 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5539, type=DOM-API, prop=spin, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 521 and loc.getEndLine() = 521 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5548, type=DOM-API, prop=home, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 835 and loc.getEndLine() = 835 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5549, type=DOM-API, prop=#home>:nth-child(7)>div>.text-7>:nth-child(1), api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 835 and loc.getEndLine() = 835 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5730, type=DOM-API, prop=sizzle1713545996388, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 9270 and loc.getEndColumn() >= 9270
        ) or 
        (   // id=5736, type=DOM-API, prop=[id~=sizzle1713545996388-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=5737, type=DOM-API, prop=[id~=sizzle1713545996388-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=5740, type=DOM-API, prop=sizzle1713545996388, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=5741, type=DOM-API, prop=a#sizzle1713545996388+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=5742, type=DOM-API, prop=a#sizzle1713545996388+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=6126, type=DOM-API, prop=sizzle1713545996388, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=6127, type=DOM-API, prop=#sizzle1713545996388 input[type="checkbox"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=6128, type=DOM-API, prop=#sizzle1713545996388 input[type="checkbox"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=6130, type=DOM-API, prop=#sizzle1713545996388 input[name="email"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=6131, type=DOM-API, prop=#sizzle1713545996388 input[name="email"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=6133, type=DOM-API, prop=#sizzle1713545996388 textarea[name="feedback"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=6134, type=DOM-API, prop=#sizzle1713545996388 textarea[name="feedback"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=7950, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 189 and loc.getEndLine() = 189 and
            loc.getStartColumn() <= 47 and loc.getEndColumn() >= 47
        ) or 
        (   // id=7971, type=DOM-API, prop=.pricing-container .price-info-container, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1291 and loc.getEndLine() = 1291 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=7972, type=DOM-API, prop=.pricing-container .price-info-container, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1291 and loc.getEndLine() = 1291 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=7974, type=DOM-API, prop=.plans-comparison-table, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1292 and loc.getEndLine() = 1292 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=7977, type=DOM-API, prop=cycle-toggle-cb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1293 and loc.getEndLine() = 1293 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=7981, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1424 and loc.getEndLine() = 1424 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7984, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1424 and loc.getEndLine() = 1424 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7985, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1518 and loc.getEndLine() = 1518 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7988, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1518 and loc.getEndLine() = 1518 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7989, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1530 and loc.getEndLine() = 1530 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7992, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1530 and loc.getEndLine() = 1530 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7994, type=DOM-API, prop=signin-form, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1699 and loc.getEndLine() = 1699 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=7995, type=DOM-API, prop=#signin-form input[type="submit"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1699 and loc.getEndLine() = 1699 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=7996, type=DOM-API, prop=#signin-form input[type="submit"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1699 and loc.getEndLine() = 1699 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=7997, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1731 and loc.getEndLine() = 1731 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7998, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1743 and loc.getEndLine() = 1743 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8001, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1743 and loc.getEndLine() = 1743 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8002, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1809 and loc.getEndLine() = 1809 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8005, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1809 and loc.getEndLine() = 1809 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8006, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1814 and loc.getEndLine() = 1814 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8009, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1814 and loc.getEndLine() = 1814 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8010, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1822 and loc.getEndLine() = 1822 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8013, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1822 and loc.getEndLine() = 1822 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8015, type=DOM-API, prop=.ui-view-email-address, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1972 and loc.getEndLine() = 1972 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=8016, type=DOM-API, prop=.ui-view-email-address, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 1972 and loc.getEndLine() = 1972 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=8018, type=DOM-API, prop=announcement, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 2000 and loc.getEndLine() = 2000 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=8122, type=DOM-API, prop=sizzle1713546000362, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 9270 and loc.getEndColumn() >= 9270
        ) or 
        (   // id=8128, type=DOM-API, prop=[id~=sizzle1713546000362-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=8129, type=DOM-API, prop=[id~=sizzle1713546000362-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=8132, type=DOM-API, prop=sizzle1713546000362, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=8133, type=DOM-API, prop=a#sizzle1713546000362+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=8134, type=DOM-API, prop=a#sizzle1713546000362+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=8506, type=DOM-API, prop=sizzle1713546000362, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=8507, type=DOM-API, prop=#sizzle1713546000362 input[type="checkbox"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=8508, type=DOM-API, prop=#sizzle1713546000362 input[type="checkbox"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=8510, type=DOM-API, prop=#sizzle1713546000362 input[name="email"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=8511, type=DOM-API, prop=#sizzle1713546000362 input[name="email"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=8513, type=DOM-API, prop=#sizzle1713546000362 textarea[name="feedback"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=8514, type=DOM-API, prop=#sizzle1713546000362 textarea[name="feedback"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=8705, type=DOM-API, prop=Non-Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8706, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8707, type=DOM-API, prop=template-name, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8708, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8709, type=DOM-API, prop=cycle-toggle-cb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8710, type=DOM-API, prop=templateName, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8712, type=DOM-API, prop=save-template-directly, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8713, type=DOM-API, prop=save-template-as-another-template, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8714, type=DOM-API, prop=deleteNoteCheck, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8715, type=DOM-API, prop=email, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8716, type=DOM-API, prop=inputEmail, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8717, type=DOM-API, prop=password, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8718, type=DOM-API, prop=inputPassword, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8719, type=DOM-API, prop=team-name, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8720, type=DOM-API, prop=team-description, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8721, type=DOM-API, prop=team-path, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8722, type=DOM-API, prop=input, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8723, type=DOM-API, prop=button, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8757, type=DOM-API, prop=helpId, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8814, type=DOM-API, prop=input[type="password"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=10016, type=DOM-API, prop=___gatsby, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=10017, type=DOM-API, prop=react-root, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/pricing.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=10110, type=DOM-API, prop=#home>:nth-child(7)>div>.text-7, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/hackmd.io/index.html") and
            loc.getStartLine() = 835 and loc.getEndLine() = 835 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=10259, type=DOM-API, prop=sizzle1713546005055, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 9270 and loc.getEndColumn() >= 9270
        ) or 
        (   // id=10265, type=DOM-API, prop=[id~=sizzle1713546005055-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=10266, type=DOM-API, prop=[id~=sizzle1713546005055-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10728 and loc.getEndColumn() >= 10728
        ) or 
        (   // id=10269, type=DOM-API, prop=sizzle1713546005055, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=10270, type=DOM-API, prop=a#sizzle1713546005055+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=10271, type=DOM-API, prop=a#sizzle1713546005055+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 10845 and loc.getEndColumn() >= 10845
        ) or 
        (   // id=10647, type=DOM-API, prop=sizzle1713546005055, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=10648, type=DOM-API, prop=#sizzle1713546005055 input[type="checkbox"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=10649, type=DOM-API, prop=#sizzle1713546005055 input[type="checkbox"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=10651, type=DOM-API, prop=#sizzle1713546005055 input[name="email"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=10652, type=DOM-API, prop=#sizzle1713546005055 input[name="email"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=10654, type=DOM-API, prop=#sizzle1713546005055 textarea[name="feedback"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ) or 
        (   // id=10655, type=DOM-API, prop=#sizzle1713546005055 textarea[name="feedback"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/a40ede4cec/source/assets.hackmd.io/build/common-vendor.f59a8489b8ce2d49b975.js") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 7220 and loc.getEndColumn() >= 7220
        ))
        ) and
        this = propRead
      )
  }
}
class IdentifiedClobberableSource extends DataFlow::Node {
    IdentifiedClobberableSource() {
    this instanceof IdentifiedClobberableSourceWinTypeOne or
    this instanceof IdentifiedClobberableSourceDocTypeOne or
    this instanceof IdentifiedClobberableSourceDocTypeTwo or
    this instanceof IdentifiedClobberableSourceDOMAPI
    }
}
predicate propReadAsTaintStep(DataFlow::Node pred, DataFlow::Node succ){
    exists(DataFlow::PropRead pr | 
        pr.getBase() = pred and
        pr.flowsTo(succ)
    )
}

class DebuggingConfig extends TaintTracking::Configuration {
// Configuration baseConfig;

DebuggingConfig() { this = "DOM-Clobbering-hackmd.io-a40ede4cec" }
    
    override predicate isSource(DataFlow::Node source) { 
    source instanceof IdentifiedClobberableSource
    }

    // Extended here to include the SocketWriteSink
    override predicate isSink(DataFlow::Node sink) { 
    sink instanceof DomBasedXss::Sink
    }

    override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    DataFlow::localFieldStep(pred, succ) or
    TaintTracking::arrayStep(pred, succ) or
    propReadAsTaintStep(pred, succ)
    }
}
from DebuggingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
"$@ is potentially clobberable and flows to the XSS sink.", source.getNode(), source.getNode().toString()
