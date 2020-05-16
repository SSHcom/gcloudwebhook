NAME := PrivXWebhook

all:
	@echo "Targets: deploy delete"

deploy:
	gcloud functions deploy $(NAME) --set-env-vars PRIVX_INSTANCE=privxdemo.ssh.engineering --runtime go113 --trigger-http

delete:
	gcloud functions delete $(NAME)
