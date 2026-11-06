package panel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/Altonomega/Nexounel/core/internal/config"
	"github.com/Altonomega/Nexounel/core/internal/multisession"
)

type nodesContent struct {
	Nodes         []RegistryNodeView
	RegistryError string
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	sess := s.sessionFromRequest(r)
	nodes, regErr := ListRegistryNodes(s.cfg.RegistryFile)
	data := s.pageData(r, sess, "Nodes")
	content := nodesContent{Nodes: nodes}
	if regErr != nil {
		content.RegistryError = regErr.Error()
	}
	data.Content = content
	s.render(w, r, "nodes", data)
}

// sshForm carries one provisioning form's SSH details. Secrets live only
// in the request's memory and in the job's memory.
type sshForm struct {
	host     string
	port     int
	username string
	password string
	keyPEM   []byte
}

func parseSSHForm(r *http.Request) (sshForm, error) {
	form := sshForm{
		host:     strings.TrimSpace(r.FormValue("ssh_host")),
		username: strings.TrimSpace(r.FormValue("ssh_user")),
		password: r.FormValue("ssh_password"),
		keyPEM:   []byte(strings.TrimSpace(r.FormValue("ssh_key"))),
	}
	if form.username == "" {
		form.username = "root"
	}
	port, err := strconv.Atoi(strings.TrimSpace(r.FormValue("ssh_port")))
	if err != nil || port < 1 || port > 65535 {
		if strings.TrimSpace(r.FormValue("ssh_port")) == "" {
			port = 22
		} else {
			return form, fmt.Errorf("invalid SSH port %q", r.FormValue("ssh_port"))
		}
	}
	form.port = port
	if form.host == "" {
		return form, fmt.Errorf("SSH target host is required")
	}
	if form.password == "" && len(form.keyPEM) == 0 {
		return form, fmt.Errorf("an SSH password or private key is required")
	}
	return form, nil
}

func (s *Server) provisionPaths() (keyFile, nodeConfig, resolversFile, binary string) {
	return "/opt/nexounel/node.key",
		"/opt/nexounel/nexounel-node.toml",
		"/opt/nexounel/client_resolvers.txt",
		"/opt/nexounel/nexounel-node"
}

func (s *Server) knownFingerprintFor(form sshForm) string {
	cfg, err := LoadConfig(s.cfgPath)
	if err != nil {
		return s.cfg.KnownHosts[net.JoinHostPort(form.host, strconv.Itoa(form.port))]
	}
	return cfg.KnownHosts[net.JoinHostPort(form.host, strconv.Itoa(form.port))]
}

// startProvisionJob runs a provisioning request in the background (or
// synchronously when syncJobs is set in tests) and redirects to the job
// page. The job id is found by listing jobs for the node when the run is
// asynchronous; the redirect goes to the jobs list in that case.
func (s *Server) startProvisionJob(w http.ResponseWriter, r *http.Request, req ProvisionRequest) {
	addr := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	factory := s.factoryForAddr(addr)
	run := func() {
		_, _ = RunProvision(context.Background(), req, factory, s.jobs)
	}
	if s.syncJobs {
		run()
		// Redirect to the newest job for this node.
		for _, job := range s.jobs.List() {
			if job.NodeID == req.NodeID {
				http.Redirect(w, r, s.cfg.WebPath+"/jobs/"+job.ID, http.StatusFound)
				return
			}
		}
		http.Redirect(w, r, s.cfg.WebPath+"/jobs", http.StatusFound)
		return
	}
	go run()
	http.Redirect(w, r, s.cfg.WebPath+"/jobs", http.StatusFound)
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	form, err := parseSSHForm(r)
	if err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = err.Error()
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	if err := validateNodeID(nodeID); err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = err.Error()
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	connectAddr := strings.TrimSpace(r.FormValue("connect_addr"))
	listenPort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("listen_port")))
	if listenPort == 0 {
		listenPort = 18000
	}
	forwardRange := strings.TrimSpace(r.FormValue("forward_range"))
	if _, _, err := config.ParsePortRange(forwardRange); err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = fmt.Sprintf("Invalid forward range: %s", err.Error())
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	// Resolve the node's key from the registry for delivery. The key is
	// used only to write the node's key file; it is never displayed or
	// logged.
	nodeKey, err := resolveRegistryKey(s.cfg.RegistryFile, nodeID)
	if err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = fmt.Sprintf("Could not resolve the node key: %s", err.Error())
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	keyFile, nodeConfig, resolversFile, binary := s.provisionPaths()
	req := ProvisionRequest{
		Mode: ProvisionInstall, Host: form.host, Port: form.port, Username: form.username,
		Password: form.password, PrivateKeyPEM: form.keyPEM,
		KnownFingerprint: s.knownFingerprintFor(form),
		NodeID:           nodeID, NodeKey: nodeKey, ConnectAddr: connectAddr,
		ListenPort: listenPort, ForwardRange: forwardRange,
		LocalBinaryPath: s.cfg.NodeBinary, LocalResolversPath: s.cfg.ResolversFile,
		KeyFilePath: keyFile, NodeConfigPath: nodeConfig,
		ResolversFilePath: resolversFile, BinaryPath: binary,
		OnFingerprintConfirmed: s.persistFingerprint,
	}
	s.startProvisionJob(w, r, req)
}

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	form, err := parseSSHForm(r)
	if err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = err.Error()
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	if err := validateNodeID(nodeID); err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = err.Error()
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	newKey, err := GenerateNodeKey()
	if err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = err.Error()
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	if err := RotateNodeKey(s.cfg.RegistryFile, nodeID, newKey); err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = fmt.Sprintf("Could not rotate the registry key: %s", err.Error())
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	s.markRestartNeeded()
	keyFile, _, _, _ := s.provisionPaths()
	req := ProvisionRequest{
		Mode: ProvisionRotate, Host: form.host, Port: form.port, Username: form.username,
		Password: form.password, PrivateKeyPEM: form.keyPEM,
		KnownFingerprint: s.knownFingerprintFor(form),
		NodeID:           nodeID, NodeKey: newKey,
		LocalBinaryPath: s.cfg.NodeBinary, LocalResolversPath: s.cfg.ResolversFile,
		KeyFilePath:            keyFile,
		OnFingerprintConfirmed: s.persistFingerprint,
	}
	s.startProvisionJob(w, r, req)
}

func (s *Server) handleDeliver(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	form, err := parseSSHForm(r)
	if err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = err.Error()
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	if err := validateNodeID(nodeID); err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = err.Error()
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	nodeKey, err := resolveRegistryKey(s.cfg.RegistryFile, nodeID)
	if err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = fmt.Sprintf("Could not resolve the node key: %s", err.Error())
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	keyFile, _, _, _ := s.provisionPaths()
	req := ProvisionRequest{
		Mode: ProvisionRotate, Host: form.host, Port: form.port, Username: form.username,
		Password: form.password, PrivateKeyPEM: form.keyPEM,
		KnownFingerprint: s.knownFingerprintFor(form),
		NodeID:           nodeID, NodeKey: nodeKey,
		LocalBinaryPath: s.cfg.NodeBinary, LocalResolversPath: s.cfg.ResolversFile,
		KeyFilePath:            keyFile,
		OnFingerprintConfirmed: s.persistFingerprint,
	}
	s.startProvisionJob(w, r, req)
}

func (s *Server) handleRemoveNode(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimSpace(r.FormValue("node_id"))
	if r.FormValue("confirm") != "yes" {
		data := s.pageData(r, sess, "Nodes")
		data.Error = "Removal requires confirmation."
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	if err := RemoveNodeFromRegistry(s.cfg.RegistryFile, nodeID); err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = fmt.Sprintf("Could not remove the node: %s", err.Error())
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	s.markRestartNeeded()
	if r.FormValue("remove_remote") != "yes" {
		data := s.pageData(r, sess, "Nodes")
		data.Message = fmt.Sprintf("Node %s was removed from the registry. Restart the server to apply the change. The remote node service was left running.", nodeID)
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	form, err := parseSSHForm(r)
	if err != nil {
		data := s.pageData(r, sess, "Nodes")
		data.Error = fmt.Sprintf("Node %s was removed from the registry, but remote removal needs SSH details: %s", nodeID, err.Error())
		s.render(w, r, "nodes", dataWithContent(data, s.nodesContent()))
		return
	}
	keyFile, _, _, _ := s.provisionPaths()
	req := ProvisionRequest{
		Mode: ProvisionRemoveRemote, Host: form.host, Port: form.port, Username: form.username,
		Password: form.password, PrivateKeyPEM: form.keyPEM,
		KnownFingerprint: s.knownFingerprintFor(form),
		NodeID:           nodeID, RemoveService: true,
		LocalBinaryPath: s.cfg.NodeBinary, LocalResolversPath: s.cfg.ResolversFile,
		KeyFilePath:            keyFile,
		OnFingerprintConfirmed: s.persistFingerprint,
	}
	s.startProvisionJob(w, r, req)
}

func (s *Server) nodesContent() nodesContent {
	nodes, regErr := ListRegistryNodes(s.cfg.RegistryFile)
	content := nodesContent{Nodes: nodes}
	if regErr != nil {
		content.RegistryError = regErr.Error()
	}
	return content
}

// resolveRegistryKey returns a node's key for provisioning delivery only.
// It must never be displayed or logged.
func resolveRegistryKey(registryPath, nodeID string) (string, error) {
	reg, err := multisession.LoadRegistry(registryPath)
	if err != nil {
		return "", err
	}
	node, ok := reg.Lookup(nodeID)
	if !ok {
		return "", fmt.Errorf("node %q is not in the registry", nodeID)
	}
	if node.Key == "" {
		return "", fmt.Errorf("node %q has no key", nodeID)
	}
	return node.Key, nil
}

// persistFingerprint saves a confirmed host-key fingerprint into the
// panel config's [known_hosts] table.
func (s *Server) persistFingerprint(hostPort, fingerprint string) {
	cfg, err := LoadConfig(s.cfgPath)
	if err != nil {
		cfg = s.cfg
	}
	if cfg.KnownHosts == nil {
		cfg.KnownHosts = map[string]string{}
	}
	cfg.KnownHosts[hostPort] = fingerprint
	if err := SaveConfig(s.cfgPath, cfg); err != nil {
		s.log.Errorf("Could not save confirmed host key fingerprint: %v", err)
	}
}

type jobsContent struct {
	Jobs []*Job
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	sess := s.sessionFromRequest(r)
	data := s.pageData(r, sess, "Jobs")
	data.Content = jobsContent{Jobs: s.jobs.List()}
	s.render(w, r, "jobs", data)
}

type jobContent struct {
	Job *Job
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	rest := strings.TrimPrefix(s.subPath(r.URL.Path), "/jobs/")
	parts := strings.SplitN(rest, "/", 2)
	jobID := parts[0]
	job, ok := s.jobs.Get(jobID)
	if !ok {
		s.generic404(w, r)
		return
	}
	// Host-key confirmation is a POST under the job path.
	if len(parts) == 2 && parts[1] == "confirm-hostkey" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		s.handleConfirmHostKey(w, r, sess, job)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	data := s.pageData(r, sess, "Job "+jobID)
	data.Refresh = job.Status == "running"
	data.Content = jobContent{Job: job}
	s.render(w, r, "job", data)
}

func (s *Server) handleConfirmHostKey(w http.ResponseWriter, r *http.Request, sess *Session, job *Job) {
	if r.FormValue("confirm") != "yes" {
		data := s.pageData(r, sess, "Job "+job.ID)
		data.Error = "Confirmation requires the checkbox."
		data.Content = jobContent{Job: job}
		s.render(w, r, "job", data)
		return
	}
	job.mu.Lock()
	fp, hostPort := job.HostKeyFingerprint, job.HostPort
	job.mu.Unlock()
	if fp == "" || hostPort == "" {
		data := s.pageData(r, sess, "Job "+job.ID)
		data.Error = "This job has no host key awaiting confirmation."
		data.Content = jobContent{Job: job}
		s.render(w, r, "job", data)
		return
	}
	s.persistFingerprint(hostPort, fp)
	data := s.pageData(r, sess, "Job "+job.ID)
	data.Message = "Fingerprint saved. Run the provisioning step again with the same details."
	data.Content = jobContent{Job: job}
	s.render(w, r, "job", data)
}
