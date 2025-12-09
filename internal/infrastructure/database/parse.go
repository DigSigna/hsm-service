package database

import (
	"fmt"
	"net/url"
	"strings"
)

func ParseMySQLConnectionString(connStr string) (string, error) {
	connStr = strings.TrimSpace(connStr)
	connStr = strings.Trim(connStr, `"'`)

	// Si es formato mysql:// lo procesamos como URL estándar
	if strings.HasPrefix(connStr, "mysql://") {
		u, err := url.Parse(connStr)
		if err != nil {
			return "", fmt.Errorf("invalid MySQL URL: %w", err)
		}

		user := u.User.Username()
		pass, _ := u.User.Password()
		host := u.Host
		db := strings.TrimPrefix(u.Path, "/")
		params := u.RawQuery

		// Convertir ssl-mode a tls
		params = strings.Replace(params, "ssl-mode=REQUIRED", "tls=true", 1)
		params = strings.Replace(params, "ssl-mode=PREFERRED", "tls=true", 1)

		// Agregar parámetros obligatorios
		if !strings.Contains(params, "tls=") {
			params += "&tls=true"
		}
		if !strings.Contains(params, "parseTime=") {
			params += "&parseTime=true"
		}
		if !strings.Contains(params, "timeout=") {
			params += "&timeout=30s"
		}

		return fmt.Sprintf(
			"%s:%s@tcp(%s)/%s?%s",
			user, pass, host, db, params,
		), nil
	}

	// Si NO empieza con mysql:// asumimos que ya es formato DSN
	// y solo nos aseguramos de los parámetros
	if !strings.Contains(connStr, "tls=") {
		if strings.Contains(connStr, "?") {
			connStr += "&tls=true"
		} else {
			connStr += "?tls=true"
		}
	}
	if !strings.Contains(connStr, "parseTime=") {
		connStr += "&parseTime=true"
	}
	if !strings.Contains(connStr, "timeout=") {
		connStr += "&timeout=30s"
	}

	return connStr, nil
}
