class ToolsInstalled

  attr_reader :yaml_file

  def initialize(yaml_file)
    @yaml_file = yaml_file
  end

  def tools
    tools = %W(testssl.sh sslscan ike-scan)
    yaml_file.issue_yaml.each do |check|
      tools << check["command"]
    end
    tools = tools.uniq
  end

  def checking_tools
    puts "Checking that all pre-requisites are present"
  end

  def check_tools
    tools.each do |tool|
      if TTY::Which.which(tool).nil?
        puts "#{tool} appears to be missing, install and add to path before proceeding\nExiting....".red.bold
        exit
      else
        puts "#{tool} appears to be installed.".green.bold
      end
    end
    puts
  end

end
