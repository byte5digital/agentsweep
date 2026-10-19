cask "agentsweep" do
  version "0.1.0"
  sha256 "eb4a19d1fd08bf78ca0f623ccf73e935f49f7b46e99f76821737289188fdc65a"

  url "https://github.com/byte5digital/agentsweep/releases/download/v#{version}/AgentSweep_#{version}_universal.dmg"
  name "AgentSweep"
  desc "Scans Claude Code and Codex settings and quarantines what a rule proves bad"
  homepage "https://github.com/byte5digital/agentsweep"

  auto_updates true
  depends_on macos: :sonoma

  app "AgentSweep.app"
  binary "#{appdir}/AgentSweep.app/Contents/MacOS/agentsweep"

  uninstall launchctl: "de.byte5.agentsweep.daemon",
            quit:      "de.byte5.agentsweep"

  zap trash: [
    "~/Library/Application Support/de.byte5.agentsweep",
    "~/Library/Caches/de.byte5.agentsweep",
    "~/Library/HTTPStorages/de.byte5.agentsweep",
    "~/Library/Logs/AgentSweep",
    "~/Library/Preferences/de.byte5.agentsweep.plist",
    "~/Library/Saved Application State/de.byte5.agentsweep.savedState",
    "~/Library/WebKit/de.byte5.agentsweep",
  ]
end
