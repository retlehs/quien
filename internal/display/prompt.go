package display

import (
	"net"
	"strings"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"

	tea "charm.land/bubbletea/v2"
)

var (
	promptTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(cyan).
				MarginBottom(1)

	promptLabelStyle = lipgloss.NewStyle().
				Foreground(dim)

	promptInputStyle = lipgloss.NewStyle().
				Foreground(white)
)

type PromptModel struct {
	textInput textinput.Model
	quitting  bool
	submitted bool
	result    string
	isIP      bool
}

func NewPromptModel() PromptModel {
	ti := textinput.New()
	ti.Placeholder = "example.com or 8.8.8.8"
	ti.Focus()
	ti.CharLimit = 253
	ti.SetWidth(40)
	ti.Prompt = "  "

	s := ti.Styles()
	s.Focused.Prompt = promptLabelStyle
	s.Focused.Text = promptInputStyle
	s.Blurred.Prompt = promptLabelStyle
	s.Blurred.Text = promptInputStyle
	ti.SetStyles(s)

	return PromptModel{
		textInput: ti,
	}
}

func (m PromptModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m PromptModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			input := strings.TrimSpace(m.textInput.Value())
			if input == "" {
				return m, nil
			}
			m.submitted = true
			m.result = strings.TrimSuffix(strings.ToLower(input), ".")
			m.isIP = net.ParseIP(m.result) != nil
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m PromptModel) View() tea.View {
	if m.quitting || m.submitted {
		return tea.NewView("")
	}

	underline := lipgloss.NewStyle().Foreground(ac("#AAAAAA", "#555555"))

	var content strings.Builder
	content.WriteString(promptTitleStyle.Render("quien"))
	content.WriteString("\n\n")
	content.WriteString(promptLabelStyle.Render("Enter a domain or IP address:"))
	content.WriteString("\n\n")
	content.WriteString(m.textInput.View())
	content.WriteString("\n")
	content.WriteString(underline.Render(strings.Repeat("─", 40)))

	outerBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(1, 3).
		Width(50)

	footer := promptLabelStyle.Render("  enter to look up • esc to quit")

	return tea.NewView("\n" + outerBox.Render(content.String()) + "\n" + footer + "\n")
}

// Result returns the submitted input and whether it's an IP.
func (m PromptModel) Result() (string, bool, bool) {
	return m.result, m.isIP, m.submitted
}
