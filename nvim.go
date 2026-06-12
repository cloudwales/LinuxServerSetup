package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// ConfigureNvim installs a recent Neovim from the official PPA, the toolchain
// the bundled LSP servers need (node/npm, go, build tools, ripgrep, fd), then
// drops a lazy.nvim-based starter config into the chosen user's home. First
// `nvim` launch bootstraps plugins and Mason auto-installs the LSP servers.
func ConfigureNvim(cfg Config) error {
	fmt.Println()
	fmt.Println(head("Neovim + LSP starter"))
	fmt.Println("  Installs: neovim, nodejs/npm, golang-go, ripgrep, fd-find, build-essential")
	fmt.Println("  Configures (via Mason on first launch): gopls, intelephense, dockerls, bashls, jsonls, lua_ls")
	fmt.Println()
	if cfg.interactive() && !confirm("Proceed?", true) {
		fmt.Println(warn("cancelled"))
		return nil
	}

	if err := task("Add Neovim stable PPA", addNvimPPA); err != nil {
		return err
	}

	if err := task("Install Neovim + LSP toolchain", installNvimPackages); err != nil {
		return err
	}

	username := readLine("Username to install nvim config for (blank to skip user config): ")
	if username == "" {
		fmt.Println(warn("no username given — toolchain installed, user config skipped"))
		return nil
	}
	if !userExists(username) {
		fmt.Println(warn("user " + username + " does not exist — skipping config"))
		return nil
	}

	if err := task("Write starter config for "+username, func() error { return writeNvimConfig(username) }); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("  First launch will bootstrap lazy.nvim and Mason will install LSP servers (~30–60s).")
	fmt.Println("  Run it as " + username + ":  sudo -iu " + username + " nvim")
	return nil
}

func addNvimPPA() error {
	if err := aptInstall("software-properties-common", "ca-certificates", "curl", "gnupg"); err != nil {
		return err
	}
	if err := run("add-apt-repository", "-y", "ppa:neovim-ppa/stable"); err != nil {
		return fmt.Errorf("add neovim PPA: %w", err)
	}
	return run("apt-get", "update")
}

func installNvimPackages() error {
	return aptInstall(
		"neovim",
		"git",
		"unzip",
		"build-essential",
		"ripgrep",
		"fd-find",
		"nodejs",
		"npm",
		"python3-pip",
		"golang-go",
	)
}

func writeNvimConfig(username string) error {
	home := "/home/" + username
	configDir := filepath.Join(home, ".config", "nvim")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return err
	}
	initPath := filepath.Join(configDir, "init.lua")

	if _, err := os.Stat(initPath); err == nil {
		if !confirm(initPath+" already exists. Overwrite?", false) {
			fmt.Println(warn("keeping existing init.lua"))
			return nil
		}
	}

	if err := os.WriteFile(initPath, []byte(nvimInitLua), 0o644); err != nil {
		return err
	}

	return run("chown", "-R", username+":"+username, filepath.Join(home, ".config"))
}

const nvimInitLua = `-- Bootstrap lazy.nvim
local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
if not (vim.uv or vim.loop).fs_stat(lazypath) then
  vim.fn.system({
    "git", "clone", "--filter=blob:none",
    "https://github.com/folke/lazy.nvim.git",
    "--branch=stable", lazypath,
  })
end
vim.opt.rtp:prepend(lazypath)

vim.g.mapleader = " "
vim.g.maplocalleader = " "

vim.opt.number = true
vim.opt.relativenumber = true
vim.opt.expandtab = true
vim.opt.shiftwidth = 2
vim.opt.tabstop = 2
vim.opt.smartindent = true
vim.opt.termguicolors = true
vim.opt.mouse = "a"
vim.opt.clipboard = "unnamedplus"
vim.opt.signcolumn = "yes"
vim.opt.updatetime = 250
vim.opt.ignorecase = true
vim.opt.smartcase = true

local servers = { "gopls", "intelephense", "dockerls", "bashls", "jsonls", "lua_ls" }

require("lazy").setup({
  {
    "folke/tokyonight.nvim",
    lazy = false,
    priority = 1000,
    config = function() vim.cmd.colorscheme("tokyonight") end,
  },

  {
    "nvim-treesitter/nvim-treesitter",
    build = ":TSUpdate",
    config = function()
      require("nvim-treesitter.configs").setup({
        ensure_installed = { "go", "php", "bash", "json", "dockerfile", "lua", "vim", "vimdoc", "yaml" },
        highlight = { enable = true },
        indent = { enable = true },
      })
    end,
  },

  { "williamboman/mason.nvim", config = true },

  {
    "williamboman/mason-lspconfig.nvim",
    dependencies = { "williamboman/mason.nvim", "neovim/nvim-lspconfig" },
    config = function()
      require("mason-lspconfig").setup({
        ensure_installed = servers,
        automatic_installation = true,
      })

      local lspconfig = require("lspconfig")
      for _, s in ipairs(servers) do
        lspconfig[s].setup({})
      end

      vim.api.nvim_create_autocmd("LspAttach", {
        callback = function(args)
          local buf = args.buf
          local map = function(k, fn) vim.keymap.set("n", k, fn, { buffer = buf }) end
          map("gd", vim.lsp.buf.definition)
          map("gD", vim.lsp.buf.declaration)
          map("gr", vim.lsp.buf.references)
          map("gi", vim.lsp.buf.implementation)
          map("K",  vim.lsp.buf.hover)
          map("<leader>rn", vim.lsp.buf.rename)
          map("<leader>ca", vim.lsp.buf.code_action)
          map("[d", vim.diagnostic.goto_prev)
          map("]d", vim.diagnostic.goto_next)
        end,
      })
    end,
  },

  { "neovim/nvim-lspconfig" },

  {
    "nvim-telescope/telescope.nvim",
    tag = "0.1.6",
    dependencies = { "nvim-lua/plenary.nvim" },
    config = function()
      local builtin = require("telescope.builtin")
      vim.keymap.set("n", "<leader>ff", builtin.find_files)
      vim.keymap.set("n", "<leader>fg", builtin.live_grep)
      vim.keymap.set("n", "<leader>fb", builtin.buffers)
    end,
  },
})
`
