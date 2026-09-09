# SMB400 Hotarun — デプロイ & 運用 Makefile
#
# 前提: デバイスが USB ブートで起動し ADB ルート取得済みであること。
# 初回のみ: Alpine + gcompat セットアップ (setup-runtime) と
#            Hotarun バイナリのデプロイ (deploy-hotarun) が必要。
#            Hotarun は https://github.com/yuchi0531/Hotarun の
#            最新リリース (`releases/latest/download`) から取得する (バージョン固定なし)。
#
# 典型的な操作:
#   make push-all           バイナリ・スクリプト・設定を一括更新
#   make start              Hotarun 起動
#   make stop               停止
#   make log                ログ確認
#   make test               BS4K ストリーム疎通確認

# ---------- 変更可能な設定 ----------
# ADB_TARGET 未指定時は adb devices から自動検出
# 複数台接続時は明示指定: make <target> ADB_TARGET=192.168.1.126:5555
ifndef ADB_TARGET
  _DETECTED := $(shell adb devices 2>/dev/null | awk '/\tdevice$$/{print $$1}')
  ifeq ($(words $(_DETECTED)),0)
    $(error No ADB device connected. Run: adb connect <ip>:<port>)
  else ifneq ($(words $(_DETECTED)),1)
    $(error Multiple ADB devices detected: $(_DETECTED) — set ADB_TARGET=<device>)
  else
    ADB_TARGET := $(_DETECTED)
  endif
endif
ADB        := adb -s $(ADB_TARGET)
DEVICE_IP  := $(firstword $(subst :, ,$(ADB_TARGET)))
DEVICE_TMP := /data/local/tmp
HOTARUN    := $(DEVICE_TMP)/hotarun

# Hotarun リリースバイナリ (ARM32, 初回デプロイ時のみ使用)
# バージョンはピン留めせず、常に GitHub の latest リリースから取得する。
# Hotarun は固定ファイル名で配布される (release.yml が v* タグで更新):
#   https://github.com/yuchi0531/Hotarun/releases/latest/download/hotarun-linux-arm32
HOTARUN_REPO     ?= yuchi0531/Hotarun
HOTARUN_BIN_NAME ?= hotarun-linux-arm32
HOTARUN_URL      ?= https://github.com/$(HOTARUN_REPO)/releases/latest/download/$(HOTARUN_BIN_NAME)
HOTARUN_SHA_URL  ?= $(HOTARUN_URL).sha256
HOTARUN_BIN      ?= tmp/$(HOTARUN_BIN_NAME)

# バイナリビルド設定
# 要件: gcc-arm-linux-gnueabi（sudo apt install gcc-arm-linux-gnueabi）
#       libssl-dev（b61dec の OpenSSL ヘッダ用）
CC_ARM       ?= arm-linux-gnueabi-gcc
ANDROID_LIBS := android-libs
# _TIME_BITS=32 / _FILE_OFFSET_BITS=32: 新しい Debian/Ubuntu のクロスツールチェーンは
# 64-bit time_t がデフォルトで __gettimeofday64 等を要求するが、Android bionic の
# libc.so は 32-bit time_t のシンボル (gettimeofday 等) しか持たないため明示的に 32-bit へ。
CFLAGS_ARM   := -march=armv7-a -mfloat-abi=softfp -mfpu=vfpv3 \
                -pie -fPIE -fno-stack-protector -nostartfiles \
                -D_TIME_BITS=32 -D_FILE_OFFSET_BITS=32 \
                -Wl,-dynamic-linker,/system/bin/linker \
                -L$(ANDROID_LIBS) -Wl,-rpath-link,$(ANDROID_LIBS)
# ------------------------------------

.PHONY: build-bins android-libs \
        push-all push-bins push-scripts push-config \
        fetch-hotarun deploy-hotarun setup-runtime \
        start stop restart log test help

# ---- ビルド (src/ → bin/) ----

# デバイスから Android システムライブラリを取得（初回のみ。ADB 接続が必要）
# bionic libc/libssl 等にリンクするため実機の .so を使用する。
android-libs:
	@mkdir -p $(ANDROID_LIBS)
	@for lib in libc.so libdl.so ld-android.so libssl.so libcrypto.so libm.so; do \
	    if [ ! -f $(ANDROID_LIBS)/$$lib ]; then \
	        echo "[*] pull /system/lib/$$lib"; \
	        $(ADB) pull /system/lib/$$lib $(ANDROID_LIBS)/$$lib; \
	    fi; \
	done

# src/ から bin/ のバイナリ（tuner-stream-bs-ng, b61dec）をビルド
build-bins: android-libs
	@mkdir -p bin
	@echo "[*] Building tuner-stream-ng (GR/ISDB-T)..."
	$(CC_ARM) $(CFLAGS_ARM) \
	    src/startup.c src/tuner-stream-ng.c \
	    $(ANDROID_LIBS)/libc.so $(ANDROID_LIBS)/libdl.so $(ANDROID_LIBS)/ld-android.so \
	    -o bin/tuner-stream-ng
	@echo "[*] Building tuner-stream-bs-ng..."
	$(CC_ARM) $(CFLAGS_ARM) \
	    src/startup.c src/tuner-stream-bs-ng.c \
	    $(ANDROID_LIBS)/libc.so $(ANDROID_LIBS)/libdl.so $(ANDROID_LIBS)/ld-android.so \
	    -o bin/tuner-stream-bs-ng
	@echo "[*] Building b61dec..."
	$(CC_ARM) $(CFLAGS_ARM) -Wl,--no-as-needed \
	    -isystem /usr/include -isystem include \
	    src/startup.c src/b61dec.c \
	    $(ANDROID_LIBS)/libssl.so $(ANDROID_LIBS)/libcrypto.so \
	    $(ANDROID_LIBS)/libc.so $(ANDROID_LIBS)/libdl.so \
	    $(ANDROID_LIBS)/libm.so $(ANDROID_LIBS)/ld-android.so \
	    -o bin/b61dec
	@echo "[*] Building tuner-stream-bs (ISDB-S mode=1)..."
	$(CC_ARM) $(CFLAGS_ARM) \
	    src/startup.c src/tuner-stream-bs.c \
	    $(ANDROID_LIBS)/libc.so $(ANDROID_LIBS)/libdl.so $(ANDROID_LIBS)/ld-android.so \
	    -o bin/tuner-stream-bs
	@echo "[*] Building b21dec (従来2K BS MULTI2 descrambler)..."
	$(CC_ARM) $(CFLAGS_ARM) -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -Wl,--no-as-needed \
	    src/startup.c src/b21dec.c \
	    $(ANDROID_LIBS)/libc.so $(ANDROID_LIBS)/libdl.so $(ANDROID_LIBS)/ld-android.so \
	    -o bin/b21dec
	@echo "[+] Built bin/tuner-stream-ng, tuner-stream-bs-ng, b61dec, tuner-stream-bs, b21dec"

# ---- デプロイ ----

push-bins:
	@echo "[*] Pushing binaries..."
	$(ADB) push bin/tuner-stream-ng    $(DEVICE_TMP)/tuner-stream-ng
	$(ADB) push bin/tuner-stream-bs-ng $(DEVICE_TMP)/tuner-stream-bs-ng
	$(ADB) push bin/b61dec             $(DEVICE_TMP)/b61dec
	$(ADB) push bin/tuner-stream-bs    $(DEVICE_TMP)/tuner-stream-bs
	$(ADB) push bin/b21dec             $(DEVICE_TMP)/b21dec
	$(ADB) shell chmod +x \
	    $(DEVICE_TMP)/tuner-stream-ng \
	    $(DEVICE_TMP)/tuner-stream-bs-ng \
	    $(DEVICE_TMP)/b61dec \
	    $(DEVICE_TMP)/tuner-stream-bs \
	    $(DEVICE_TMP)/b21dec

push-scripts:
	@echo "[*] Pushing scripts..."
	$(ADB) push scripts/smb400-tuner.sh    $(DEVICE_TMP)/smb400-tuner.sh
	$(ADB) push scripts/start_hotarun.sh   $(DEVICE_TMP)/start_hotarun.sh
	$(ADB) push scripts/stop_android_tv.sh $(DEVICE_TMP)/stop_android_tv.sh
	$(ADB) push scripts/crash_guard.sh     $(DEVICE_TMP)/crash_guard.sh
	$(ADB) shell chmod +x \
	    $(DEVICE_TMP)/smb400-tuner.sh \
	    $(DEVICE_TMP)/start_hotarun.sh \
	    $(DEVICE_TMP)/stop_android_tv.sh \
	    $(DEVICE_TMP)/crash_guard.sh

push-config:
	@echo "[*] Pushing config..."
	$(ADB) shell mkdir -p $(HOTARUN)/config
	$(ADB) push config/tuners.yml   $(HOTARUN)/config/tuners.yml
	$(ADB) push config/channels.yml $(HOTARUN)/config/channels.yml
	$(ADB) push config/server.yml   $(HOTARUN)/config/server.yml

push-all: push-bins push-scripts push-config
	@echo "[+] Done. Run 'make start' to launch Hotarun."

# Hotarun 最新リリースバイナリ (ARM32) を取得 (バージョン固定なし)
# scripts/fetch-hotarun.sh が releases/latest/download から取得・SHA-256 検証する。
fetch-hotarun:
	bash scripts/fetch-hotarun.sh $(dir $(HOTARUN_BIN))

# 初回のみ: Hotarun バイナリ一式をデプロイ
# `make fetch-hotarun` で取得した最新バイナリをデバイスへ転送する。
deploy-hotarun: fetch-hotarun
	@echo "[*] Deploying Hotarun binary to device..."
	$(ADB) shell mkdir -p $(HOTARUN)/config
	$(ADB) push $(HOTARUN_BIN) $(HOTARUN)/hotarun
	$(ADB) shell chmod +x $(HOTARUN)/hotarun
	$(ADB) push config/tuners.yml   $(HOTARUN)/config/tuners.yml
	$(ADB) push config/channels.yml $(HOTARUN)/config/channels.yml
	$(ADB) push config/server.yml   $(HOTARUN)/config/server.yml
	@echo "[+] Hotarun deployed."

# 初回のみ: Alpine ARM32 + gcompat をデバイスに構築（インターネット接続必要）
setup-runtime:
	bash scripts/setup_proot.sh $(ADB_TARGET)

# ---- 起動・停止 ----

start:
	@echo "[*] Stopping any existing session..."
	-$(ADB) shell "pkill -9 hotarun 2>/dev/null; \
	    kill -9 \$$(pgrep -f 'start_hotarun[.]sh' 2>/dev/null) 2>/dev/null; \
	    pkill -9 b61dec 2>/dev/null; pkill -9 tunertest 2>/dev/null; true"
	@sleep 2
	@echo "[*] Starting Hotarun..."
	$(ADB) shell "setsid sh $(DEVICE_TMP)/start_hotarun.sh \
	    >> $(DEVICE_TMP)/hotarun.log 2>&1 &"
	@echo "[*] 起動を待っています（最大 ~60 秒）..."
	@ok=0; for i in $$(seq 1 30); do \
	    if curl -s --max-time 5 http://$(DEVICE_IP):40772/api/version >/dev/null 2>&1; then ok=1; break; fi; \
	    sleep 2; \
	done; \
	if [ $$ok = 1 ]; then \
	    printf "[+] Hotarun is up: "; curl -s --max-time 5 http://$(DEVICE_IP):40772/api/version; echo; \
	else \
	    echo "(まだ応答がありません — 'make log' で確認してください)"; \
	fi

stop:
	-$(ADB) shell "pkill -9 hotarun 2>/dev/null; \
	    kill -9 \$$(pgrep -f 'start_hotarun[.]sh' 2>/dev/null) 2>/dev/null; \
	    pkill -9 b61dec 2>/dev/null; \
	    pkill -9 b21dec 2>/dev/null; \
	    pkill -9 tunertest 2>/dev/null; \
	    pkill -9 -f tuner-stream 2>/dev/null; \
	    sleep 1; true"
	-$(ADB) shell " \
	    grep hotarun-root /proc/mounts | while read d mp r; do echo \"\$$mp\"; done | sort -r | \
	    while read mp; do umount \"\$$mp\" 2>/dev/null || true; done; true"
	@echo "Stopped."

restart: stop start

# ---- 確認 ----

log:
	$(ADB) shell "tail -50 $(DEVICE_TMP)/hotarun.log"

# BS4K 45168 から 5 秒受信して先頭バイトを表示
# 正常: 7f 02 ... または 7f 03 ... (IPv4/IPv6 TLV コンテンツ)
# 異常: 7f ff ... (Null TLV = 未復号) またはデータなし
test:
	@echo "Streaming BS4K 45168 for 5s..."
	@curl -s --max-time 8 http://$(DEVICE_IP):40772/api/channels/BS4K/45168/stream \
	    | od -v -t x1 2>/dev/null | head -4

# ---- ヘルプ ----

help:
	@echo ""
	@echo "SMB400 Hotarun デプロイ Makefile"
	@echo ""
	@echo "  make build-bins        src/ から bin/ のバイナリをビルド (初回のみ)"
	@echo "  make android-libs      デバイスから Android システムライブラリを取得"
	@echo "  make push-all          バイナリ・スクリプト・設定を一括デプロイ"
	@echo "  make push-bins         バイナリのみ (tuner-stream-bs-ng, b61dec)"
	@echo "  make push-scripts      スクリプトのみ (smb400-tuner.sh 等)"
	@echo "  make push-config       設定ファイルのみ (channels.yml 等)"
	@echo "  make fetch-hotarun     Hotarun 最新リリースを取得 (バージョン固定なし)"
	@echo "  make deploy-hotarun    Hotarun バイナリ一式をデプロイ (初回のみ)"
	@echo "  make setup-runtime     Alpine + gcompat をデバイスに構築 (初回のみ)"
	@echo "  make start             Hotarun 起動"
	@echo "  make stop              Hotarun 停止"
	@echo "  make restart           再起動"
	@echo "  make log               ログ確認 (tail -50)"
	@echo "  make test              BS4K ストリーム疎通テスト"
	@echo ""
	@echo "デフォルト接続先: $(ADB_TARGET)"
	@echo "変更: make start ADB_TARGET=192.168.1.100:5555"
	@echo ""
