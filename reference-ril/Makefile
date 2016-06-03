export USE_NDK=1
NDK_BUILD=/android/android-ndk/android-ndk-r10e/ndk-build
NDK_PROJECT_PATH=`pwd`
NDK_DEBUG=0
APP_ABI=armeabi,x86,arm64-v8a#,mips,armeabi-v7a,mips64,x86_64
APP_BUILD_SCRIPT=Android.mk
NDK_OUT=../out/reference-ril
NDK_LIBS_OUT=../libquectel-ril

libquectel-ril: clean
	$(NDK_BUILD) V=0 NDK_OUT=$(NDK_OUT)  NDK_LIBS_OUT=$(NDK_LIBS_OUT) APP_BUILD_SCRIPT=$(APP_BUILD_SCRIPT) NDK_PROJECT_PATH=$(NDK_PROJECT_PATH) NDK_DEBUG=$(NDK_DEBUG) APP_ABI=$(APP_ABI)

clean:
	rm -rf $(NDK_OUT) $(NDK_LIBS_OUT)
	find . -name "*~" | xargs rm -f
