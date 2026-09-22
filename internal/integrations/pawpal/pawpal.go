package pawpal

import (
	"crypto/subtle"
	"fmt"
	"strconv"

	"github.com/bootdotdev/learn-web-security/internal/httpx"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey string, payload any) WebhookVerification {
	if len(providedKey) != len(expectedKey) || subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderIDValue, ok := payloadRecord["orderId"].(float64)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderID, valid := httpx.ParseSafeInteger(strconv.FormatFloat(orderIDValue, 'f', -1, 64))
	if !valid || orderID <= 0 {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	status, ok := payloadRecord["status"].(string)
	if !ok || status != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: orderID}
}
