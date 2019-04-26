set(COMPONENT_SRCS "app_main.c"
                   "app_prov.c"
                   "app_prov_handlers.c")
set(COMPONENT_ADD_INCLUDEDIRS ".")



set(COMPONENT_EMBED_TXTFILES "device_priv_1024.pem" "device_pub_1024.pem" "cloud_pub_1024.pem")

register_component()
