NAME := PrivXWebhook

all:
	@echo "Targets: deploy delete"

deploy:
	gcloud functions deploy $(NAME) --runtime go113 --trigger-http

delete:
	gcloud functions delete $(NAME)
