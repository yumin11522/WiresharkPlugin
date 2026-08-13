# WiresharkPlugin
There is the Video and Audio plugin for Wireshark

Wireshark的音视频插件

# 更新说明

当前版本自测支持 **Wireshark 4.4 / 4.6+**（Lua 5.4）。

相对旧版插件的主要兼容修复：
- 使用 Wireshark 自带的全局 `bit`（Lua BitOp），不再 `require("bit32")`（Lua 5.4 无此库）
- 同时放置 `rtp_ps_assemble.lua` 与 `rtp_ps_no_assemble.lua` 时不再因 Proto 重名导致加载失败（自动优先 assemble 版本）
- `rtp_ps_export.lua` 延迟查找 `ps` 字段，避免因插件字母序加载早于 PS 解析器而失败

# 文件说明

> [!IMPORTANT]
> *rtp_ps_no_assemble.lua*不能与*rtp_ps_assemble.lua*同时启用解析同一路流。
> 若两个文件都放在插件目录中，Wireshark 4.x 下会自动跳过 no_assemble（保留 assemble）。
> 若只要 no_assemble，请从插件目录中移除 assemble 文件。

*rtp_h264_export.lua*用于解析RTP包中的H264编码数据。本插件参考作者HuangQiangxiong(qiangxiong.huang@gmail.com)所作的H264解析插件，并进行了修改。

*rtp_h265_export.lua*用于解析RTP包中的H265编码数据，并提取裸数据到码流文件中。

*rtp_ps_no_assemble.lua*为早期的不组合ps，直接对每一个RTP数据进行解析。

*rtp_ps_assemble.lua*通过把ps流组装完整后解析数据。

*rtp_ps_export.lua*插件用于实现对PS媒体流进行解析及导出ps裸流到文件中。同时也可以直接使用ps中的相应媒体协议导出媒体数据流。

*rtp_pcma_export.lua*、*rtp_pcmu_export.lua*、*rtp_silk_export.lua*、*rtp_g729_export.lua*、*rtp_amr_export.lua*等插件用于对RTP流中的相应格式的音频流进行解析并导出成文件。

*tcp_sms.lua*用于解析 **SMS Media（TCP，默认 8060）** 二进制帧，并支持从 VIDEO 帧导出 Annex-B 裸流（H264/H265）。菜单：`Tools → Video/Export SMS Video (H264/H265)`。协议格式见 mult-player `doc/SMS流交互协议.md`。


# 加载插件方法

在Wireshark的About(关于)页面Folders(文件夹)目录下Personal plugins(个人Lua插件)对应的目录中存放lua插件文件。本方法中的插件只能存放在该的目录下，不能识别该目录下的子目录。

请只复制 `*.lua` 到该目录，不要把整个仓库目录嵌套进去。

# 插件中直接播放媒体

如果需要在插件中直接播放媒体，需要使用到ffmpeg程序。

为了在Wireshark中直接点击插件对话框的 play 按钮进行播放，需要额外准备ffmpeg可执行程序。
把下载的ffmpeg可执行程序解压后，需设置好系统变量 FFMPEG=<ffmpeg bin所在目录> ，以便可以直接执行 $FFMPEG/bin/ffmpeg -version或者(%FFMPEG%/bin/ffmpeg -version) ，并正常输出ffmpeg信息。


# ffmpeg二进制文件下载

下载ffmpeg可执行程序
从 2020.09.18 开始原来的 https://ffmpeg.zeranoe.com/builds/ 已经彻底关闭
新的编译下载地址移到 https://github.com/BtbN/FFmpeg-Builds/releases
