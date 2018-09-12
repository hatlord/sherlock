class YamlReader

  attr_reader :issue_yaml

  def initialize
    @vulndir    = File.expand_path(File.dirname("#{__FILE__}") + "/../vulns")
    @issue_yaml = YAML.load_file("#{@vulndir}/vulns.yml")
  end

  def checks
    @issue_yaml
  end

end
