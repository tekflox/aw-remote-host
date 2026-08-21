---
repo: architecture
path: docs/architecture/aw-remote-host.md
source: generated
edited: false
checksum: sha256:e24b3f4f04c73d6e15dbd1e95c01c3abc5f357aef72acd94d5aea79a8121b24d
---
# aw-remote-host

- **repo**: aw-remote-host
- **layer**: cli
- **technologies**: go
- **health** (derived): planned

The BYOD bootstrap client for Agentic Workspace — a small Go CLI you run on your own machine to link it to the AW control plane and stand up the local runtime (podman, Postgres+pgvector, Redis, the aw-workspace container) your workspace runs on.

## Connections
_none_

## MCP tools
_none exposed_

## Requirements
### Auto-update guarda o binário anterior e volta sozinho se o novo não se declarar bom
- Given o agente que roda na máquina do usuário se atualiza sozinho, e se o binário novo não subir não há ninguém do outro lado para reverter — a máquina simplesmente some do controle
- When a atualização é preparada e o vigia é armado (repos/aw-remote-host/internal/updater/updater.go::Prepare:50, cópia de segurança em :66-68, monitor em ::StartRollbackMonitor:94)
- Then o binário atual é copiado para aw-remote-host.previous ANTES de qualquer troca e um marcador pending é gravado; um processo destacado dorme o timeout de validação e, SE o marcador ainda existir, restaura a cópia, dá chmod 755 e reinicia pelo comando certo do serviço — o slug entra no comando porque o label do launchd depende dele. O binário novo que sobe bem apaga o marcador (::ClearPending:83) e o monitor não faz nada. Sem o marcador como condição, o rollback dispararia também em cima de uma atualização bem-sucedida; sem a cópia prévia não há para onde voltar, e uma atualização ruim vira uma visita física à máquina
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: _none linked_

### Sessão TCP repetida fecha a anterior, e falha de dial é reportada em vez de pendurar
- Given o túnel multiplexa várias sessões TCP por id sobre uma conexão só, e o id vem do outro lado — nada impede que chegue repetido
- When uma sessão é aberta (repos/aw-remote-host/internal/tcpproxy/tcpproxy.go::Handler.OpenTCP:68, validação do alvo em :71, fechamento do anterior em :85-87)
- Then um id já em uso fecha o socket anterior antes de guardar o novo, um alvo inválido (host vazio, porta fora de 1..65535) é recusado antes de qualquer dial, um dial que falha volta como erro em vez de deixar o chamador esperando, o EOF remoto dispara exatamente uma vez, e CloseTCP é idempotente com CloseAllTCP drenando o resto. Sobrescrever o mapa sem fechar órfã o socket anterior: ele fica aberto sem nenhum id que o alcance, e o vazamento só aparece como descritores de arquivo acabando horas depois, longe da causa
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: _none linked_

### O atalho de LAN só anuncia endereço privado, e só existe se o certificado estiver no lugar
- Given o host anuncia ao control plane em quais IPs ele é alcançável direto, e esses IPs vão parar num registro A público que qualquer um resolve
- When os endereços são coletados e o certificado do fast path é localizado (repos/aw-remote-host/internal/lanfastpath/lanfastpath.go::LANAddrs:105 e ::LocateCert:82)
- Then só entram IPv4 de faixa RFC-1918 em interfaces up e não-loopback — um IP público de uma interface qualquer nunca é anunciado — e o fast path só liga quando cert e chave existem em ~/.aw-remote-host/tls, com a porta e o alvo caindo em default explícito quando não configurados. Anunciar um endereço público aqui publica no DNS a rota direta para a máquina de alguém, e é irreversível no sentido que importa: já foi resolvido e cacheado antes de qualquer correção
- intended_status: `not_implemented` · derived health: `not_implemented`
- tests: _none linked_
