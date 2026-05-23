package main

type ServerStage int

const (
	StageNew ServerStage = iota
	StageInUse
)

func (s ServerStage) String() string {
	switch s {
	case StageNew:
		return "new"
	case StageInUse:
		return "in-use"
	}
	return "unknown"
}

type Distro int

const (
	DistroUbuntu Distro = iota
	DistroOther
)

type Config struct {
	Stage  ServerStage
	Distro Distro
}

// interactive returns true when the user should be prompted before
// potentially disruptive actions (i.e. on a server already in use).
func (c Config) interactive() bool {
	return c.Stage == StageInUse
}
