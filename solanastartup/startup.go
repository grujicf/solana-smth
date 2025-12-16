package solanastartup

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func StartSolanaTestValidator() (*exec.Cmd, error) {
	fmt.Println("🚀 Pokretanje Solana test validatora...")

	cmd := exec.Command("solana-test-validator")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("greška pri pokretanju validatora: %w", err)
	}

	// Čekaj da se validator pokrene
	fmt.Println("⏳ Čekanje da se validator pokrene...")
	time.Sleep(5 * time.Second)

	fmt.Println("✅ Validator je pokrenut!")
	return cmd, nil
}
