package display

import (
	"image/color"
	"os"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type themeMode int

const (
	themeAuto themeMode = iota
	themeLight
	themeDark
)

var (
	configuredTheme   = parseTheme(os.Getenv("QUIEN_THEME"))
	hasDarkBackground = configuredTheme != themeLight
)

type adaptiveColor struct {
	light color.Color
	dark  color.Color
}

func (c adaptiveColor) RGBA() (uint32, uint32, uint32, uint32) {
	if hasDarkBackground {
		return c.dark.RGBA()
	}
	return c.light.RGBA()
}

func parseTheme(value string) themeMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "light":
		return themeLight
	case "dark":
		return themeDark
	default:
		return themeAuto
	}
}

// ac returns a color that follows QUIEN_THEME. Auto mode starts with the dark
// palette and updates from Bubble Tea's background-color report in TUI views.
func ac(light, dark string) adaptiveColor {
	return adaptiveColor{light: lipgloss.Color(light), dark: lipgloss.Color(dark)}
}

func backgroundColorCmd() tea.Cmd {
	if configuredTheme != themeAuto {
		return nil
	}
	return tea.RequestBackgroundColor
}

func applyBackgroundColor(isDark bool) {
	if configuredTheme == themeAuto {
		hasDarkBackground = isDark
	}
}
