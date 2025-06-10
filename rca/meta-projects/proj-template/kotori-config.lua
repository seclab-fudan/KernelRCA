
add_plugin("SyscallTracer")

add_plugin("KotoriPlugin")
pluginsConfig.KotoriPlugin = {
	modules = {
		"crash_id"
	},
	logfile = "log_file_path",
	main_offset = 0x0
}

dofile('kotori-config-functiontracer.lua')
