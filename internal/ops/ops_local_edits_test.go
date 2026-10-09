package ops

import (
	"context"
	"strings"
	"testing"
)

// Um Runner falso que responde por prefixo de comando, para exercitar as duas
// guardas sem um checkout git de verdade.
type scriptedRunner struct {
	replies map[string]string // substring do comando -> stdout
	errs    map[string]error  // substring do comando -> erro
	seen    []string
}

func (r *scriptedRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.seen = append(r.seen, cmd)
	for frag, err := range r.errs {
		if strings.Contains(cmd, frag) {
			return "", err
		}
	}
	for frag, out := range r.replies {
		if strings.Contains(cmd, frag) {
			return out, nil
		}
	}
	return "", nil
}

func (r *scriptedRunner) ran(frag string) bool {
	for _, c := range r.seen {
		if strings.Contains(c, frag) {
			return true
		}
	}
	return false
}

func handlerWith(r Runner) *Handler { return &Handler{Runner: r} }

func TestUncommittedEditsBlockTheSync(t *testing.T) {
	r := &scriptedRunner{replies: map[string]string{
		"status --porcelain": " M src/apps/reconciler.py\n M Dockerfile\n",
	}}
	emit, msgs := collectEmits()

	err := handlerWith(r).guardHostUncommittedEdits(
		context.Background(), "/opt/aw-workspace", false, emit)

	if err == nil {
		t.Fatal("deixou passar um sync que apagaria 2 edições não commitadas")
	}
	joined := strings.Join(*msgs, " ")
	for _, want := range []string{"refusing to sync", "reconciler.py", "force=true"} {
		if !strings.Contains(joined, want) {
			t.Errorf("mensagem não diz %q — o usuário precisa saber o que fazer: %s", want, joined)
		}
	}
}

func TestForceDiscardsLocalEditsButSaysSo(t *testing.T) {
	r := &scriptedRunner{replies: map[string]string{
		"status --porcelain": " M src/apps/reconciler.py\n",
	}}
	emit, msgs := collectEmits()

	if err := handlerWith(r).guardHostUncommittedEdits(
		context.Background(), "/opt/aw-workspace", true, emit); err != nil {
		t.Fatalf("force=true deveria permitir: %v", err)
	}
	joined := strings.Join(*msgs, " ")
	if !strings.Contains(joined, "WILL discard") {
		t.Errorf("force não avisou que descarta o trabalho: %s", joined)
	}
}

// A armadilha que esta mudança quase criou: se untracked contasse, a guarda
// dispararia em todo host real — um workspace vivo acumula arquivos o tempo
// todo — e uma guarda que sempre dispara acaba desligada.
func TestUntrackedFilesDoNotBlock(t *testing.T) {
	r := &scriptedRunner{replies: map[string]string{
		"status --porcelain": "?? .tmp/scratch\n?? logs/boot.log\n!! node_modules/\n",
	}}
	emit, _ := collectEmits()

	if err := handlerWith(r).guardHostUncommittedEdits(
		context.Background(), "/opt/aw-workspace", false, emit); err != nil {
		t.Fatalf("untracked/ignored não devem bloquear: %v", err)
	}
}

func TestACleanTreeIsNotBlocked(t *testing.T) {
	r := &scriptedRunner{replies: map[string]string{"status --porcelain": "\n"}}
	emit, _ := collectEmits()

	if err := handlerWith(r).guardHostUncommittedEdits(
		context.Background(), "/opt/aw-workspace", false, emit); err != nil {
		t.Fatalf("árvore limpa não pode bloquear: %v", err)
	}
}

// Um host sem git (ou sem checkout) nunca pode ser impedido de atualizar —
// falhar fechado ali estrangularia todo host que nunca teve repo.
func TestAHostWithoutGitIsNotBlocked(t *testing.T) {
	r := &scriptedRunner{errs: map[string]error{
		"status --porcelain": context.Canceled, // qualquer erro serve
	}}
	emit, _ := collectEmits()

	if err := handlerWith(r).guardHostUncommittedEdits(
		context.Background(), "/opt/aw-workspace", false, emit); err != nil {
		t.Fatalf("host sem git deve seguir: %v", err)
	}
}

func TestRealignMovesHeadToTheImageCommit(t *testing.T) {
	r := &scriptedRunner{replies: map[string]string{
		"rev-parse --git-dir":        ".git\n",
		"rev-parse v0.49.0^{commit}": "7524dd03fd1c7fafb5fc4a7d4617788e7c6382e6\n",
	}}
	emit, msgs := collectEmits()

	handlerWith(r).realignHostGitHead(
		context.Background(), "/opt/aw-workspace", "v0.49.0", emit)

	if !r.ran("reset --mixed 7524dd03fd1c7fafb5fc4a7d4617788e7c6382e6") {
		t.Fatalf("não moveu o HEAD para o commit da imagem; chamadas: %v", r.seen)
	}
	if !strings.Contains(strings.Join(*msgs, " "), "realigned") {
		t.Errorf("realinhou em silêncio — isso precisa aparecer no log do update")
	}
}

// reset --mixed e NUNCA --hard: a árvore já é o conteúdo da imagem neste
// ponto, e um --hard também apagaria o que a imagem não traz.
func TestRealignNeverUsesHardReset(t *testing.T) {
	r := &scriptedRunner{replies: map[string]string{
		"rev-parse --git-dir":        ".git\n",
		"rev-parse v0.49.0^{commit}": "7524dd0\n",
	}}
	emit, _ := collectEmits()

	handlerWith(r).realignHostGitHead(
		context.Background(), "/opt/aw-workspace", "v0.49.0", emit)

	if r.ran("reset --hard") {
		t.Fatal("usou --hard: isso apagaria arquivos que a imagem não traz")
	}
}

func TestRealignIsSilentlySkippedForADevImage(t *testing.T) {
	for _, version := range []string{"", "dev", "   "} {
		r := &scriptedRunner{}
		emit, _ := collectEmits()
		handlerWith(r).realignHostGitHead(context.Background(), "/opt/aw-workspace", version, emit)
		if len(r.seen) != 0 {
			t.Errorf("version=%q não deveria tocar em git: %v", version, r.seen)
		}
	}
}

// Um host cujo git não resolve o commit da imagem fica exatamente como
// estava — transformar um desalinhamento cosmético em update travado seria
// pior que o problema.
func TestRealignLeavesAnUnresolvableHostAlone(t *testing.T) {
	r := &scriptedRunner{
		replies: map[string]string{"rev-parse --git-dir": ".git\n"},
		errs:    map[string]error{"rev-parse v0.49.0^{commit}": context.Canceled},
	}
	emit, msgs := collectEmits()

	handlerWith(r).realignHostGitHead(
		context.Background(), "/opt/aw-workspace", "v0.49.0", emit)

	if r.ran("reset") {
		t.Fatal("tentou resetar para um commit que o host não conhece")
	}
	if !strings.Contains(strings.Join(*msgs, " "), "could not resolve") {
		t.Errorf("falhou em silêncio; mensagens: %v", *msgs)
	}
}
