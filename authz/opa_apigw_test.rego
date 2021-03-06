package apigw

authz_policies = [{
	"resource": "/service1/[0-9]+/some",
	"operations": ["GET", "PUT"],
	"allowed_to": {
		"user_groups": ["POC-GRP", "Green_Group"],
		"web_app_client_ids": ["11512cenrga5le8239ambvnva1"],
		"system_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji", "Green"],
	},
}]

test_get_on_service1_allowed {
	allow with input as {"operation": "GET", "resource": "/service1/123/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies
}

test_put_on_service1_allowed {
	allow with input as {"operation": "PUT", "resource": "/service1/123/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies
}

test_post_on_service1_denied {
	not allow with input as {"operation": "POST", "resource": "/service1/123/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies
}

test_get_on_service1_wrong_path__denied {
	not allow with input as {"operation": "GET", "resource": "/service1/123a/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies
}

authz_policies_2 = [{
	"resource": "/service1/[0-9]+/some",
	"operations": ["GET", "PUT"],
	"allowed_to": {
		"user_groups": ["POC-GRP-Shivaji", "Green_Group"],
		"web_app_client_ids": ["11512cenrga5le8239ambvnva1"],
		"system_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji", "Green"],
	},
}]

test_get_on_service1_wrong_user_group_denied {
	not allow with input as {"operation": "POST", "resource": "/service1/123/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies_2
}

authz_policies_3 = [{
	"resource": "/service1/[0-9]+/some",
	"operations": ["GET", "PUT"],
	"allowed_to": {
		"user_groups": ["POC-GRP", "Green_Group"],
		"web_app_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji"],
		"system_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji", "Green"],
	},
}]

test_get_on_service1_wrong_web_app_client_id_denied {
	not allow with input as {"operation": "POST", "resource": "/service1/123/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies_3
}

authz_policies_4 = [{
	"resource": "/service1/[0-9]+/some",
	"operations": ["GET", "PUT"],
	"allowed_to": {
		"user_groups": ["POC-GRP-Shivaji", "Green_Group"],
		"web_app_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji"],
		"system_client_ids": ["11512cenrga5le8239ambvnva1", "Green"],
	},
}]

test_get_on_service1_batch_client_id_allowed {
	not allow with input as {"operation": "POST", "resource": "/service1/123/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies_4
}

authz_policies_5 = [{
	"resource": "/service1/[0-9]+/some",
	"operations": ["GET", "PUT"],
	"allowed_to": {
		"user_groups": ["POC-GRP-Shivaji", "Green_Group"],
		"web_app_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji"],
		"system_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji", "Green"],
	},
}]

test_get_on_service1_non_matched_denied {
	not allow with input as {"operation": "POST", "resource": "/service1/123/some", "token": "eyJraWQiOiJTeFB0NVdnVWtPXC9lYlNVTklxNDM0T2pzRXJTeENIWlFaVVVheDN6R2FEdz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiZjFkZjg2Yi1jMTRkLTQ4NGYtYWNhMS0wZmY1YjM2ZTNhMTIiLCJjb2duaXRvOmdyb3VwcyI6WyJQT0MtR1JQIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC5hcC1zb3V0aGVhc3QtMi5hbWF6b25hd3MuY29tXC9hcC1zb3V0aGVhc3QtMl9EQmxURUpRRmciLCJ2ZXJzaW9uIjoyLCJjbGllbnRfaWQiOiIxMTUxMmNlbnJnYTVsZTgyMzlhbWJ2bnZhMSIsIm9yaWdpbl9qdGkiOiJhZDZhZGZkMy0zN2NlLTQxOWUtYWE4OS05MzUwMDNmYTFlNDEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6Im9wZW5pZCBQT0NSU1wvUE9DUlMtU0NPUEUiLCJhdXRoX3RpbWUiOjE2MjQ4MzQwNzEsImV4cCI6MTYyNDgzNzY3MSwiaWF0IjoxNjI0ODM0MDcxLCJqdGkiOiI3OGQzMzUyYS1jY2FhLTQzZTctYjExZS02ODViMTU3MDlmZmYiLCJ1c2VybmFtZSI6InNoaXZhamkifQ.hCzVYILXTNUXZm0ohHbEfGqSCLY_JWWIvfJdOWMdA2eLgbk-g_YOltJF_DaP2CWQQOXGbkRz53zb1PZbHE5fB0smbuAVZVSBbGY9SLtuNgYkTmrbP8C-tdVFJkg0xuAL6QLpZpmSonQPMVzfwewyAYhzY1Hwu1Gr-G-eu16nV9fyNh2WhhLACyw1a53_pHZLp04j4Foo91A6kSUR4VOiSNWz6jdYFUAIijZdNY6O9JCivn8S3oGdrH7O-f6ksNCrucxyek9TKcgtWXvsiXReewwkPX2GgCb3YLGEQfkdAh4XhRqKDc3DVn-O7s3YsrXyXQ07CgBDenxvkrz-shH8mg"}
		 with data.authzs as authz_policies_5
}

authz_policies_6 = [{
	"resource": "/service1/[0-9]+/some",
	"operations": ["GET", "PUT"],
	"allowed_to": {
		"user_groups": ["POC-GRP-Shivaji", "Green_Group"],
		"web_app_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji"],
		"system_client_ids": ["11512cenrga5le8239ambvnva1-Shivaji", "Green"],
	},
}]

test_get_on_service1_on_missing_token_denied {
	not allow with input as {"operation": "POST", "resource": "/service1/123/some"}
		 with data.authzs as authz_policies_6
}
