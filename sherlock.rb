#!/usr/bin/env ruby
#Sherlock is a pen test proof of concept tool. It takes a .nessus file as input and then attempts to verify using other tools.
#Version 0.9
require 'pp'
require 'tty'
require 'yaml'
require 'logger'
require 'colorize'
require 'nokogiri'
require 'fileutils'
require 'threadify'
require 'text-table'
require_relative 'lib/banner'
require_relative 'lib/prereqs'
require_relative 'lib/sslscrape'
require_relative 'lib/filewriter'
require_relative 'lib/yaml_reader'
require_relative 'lib/parse_nessus'

puts Banner.new.banner.blue

if ARGV.empty?
  puts "You didn't provide a Nessus folder location!.\nUsage: ./sherlock.rb /path/to/your/nessusfolder/".red.bold
  exit
end

class BuildChecks

  attr_reader :nessus, :vuln_array, :yaml_file, :basedir
  attr_accessor :check_array

  def initialize(nessus, yaml_file, tool_installed)
    @nessus         = nessus
    @yaml_file      = yaml_file
    @vuln_array     = nessus.vuln_array
    @vuln_array     = vuln_array
    @check_array    = []
    @tool_installed = tool_installed
  end

  def directory
    time       = Time.now.strftime("%d%b%Y_%H%M%S")
    @basedir   = "#{Dir.home}/Documents/Sherlock_Out/Sherlock_#{time}"
    FileUtils.mkdir_p(@basedir) unless File.exists?(@basedir)
  end

  def remove_checks
    #removes checks for tools that are not installed
    temp_array = []
    yaml_file.checks.each do |inner_hash|
      @tool_installed.tool_present.each do |tool|
        if inner_hash.has_value?(tool)
          temp_array << inner_hash
        end
      end
    end
    @final_commands = temp_array
  end

  def final_checks
    @final_commands.each do |check|
      vuln_array.each do |vuln|
        if check['pluginid'] == vuln[:pluginid]
          check['ip']        = vuln[:ip]
          check['port']      = vuln[:port]
          check['finalargs'] = check['arguments'].gsub("_ip_", check['ip']).gsub("_port_", check['port']).gsub("_dir_", @basedir)
          check_array << check.dup
        end
      end
    end
    check_array
  end

end

class Scanner

  attr_reader :out, :err, :log, :cmd
  attr_accessor :buildchecks

  def initialize(buildchecks)
    @log         = Logger.new('debug.log')
    @buildchecks = buildchecks.final_checks
    @cmd = TTY::Command.new(output: log)
  end

  def run_command
    buildchecks.threadify do |check|
      command      = "#{check['command']} #{check['finalargs']}"
      out, err     = cmd.run!(check['command'] + " " + check['finalargs'], timeout: check['timeout'])
      check['out'] = "#{command}\n#{out}"
      puts "Running: #{command} for issue: #{check['name']}"
      rescue TTY::Command::TimeoutExceeded => @timeout_error
      puts "Timeout: #{command}".red.bold if @timeout_error
    end
  end

end



yaml_file = YamlReader.new
tool_installed = ToolsInstalled.new(yaml_file)
tool_installed.checking_tools
tool_installed.check_tools
nessus = ParseNessus.new
nessus.choose_nessus_files
nessus.parse_nessus_file
buildchecks = BuildChecks.new(nessus, yaml_file, tool_installed)
buildchecks.directory
buildchecks.remove_checks
scanner = Scanner.new(buildchecks)
scanner.run_command
sslscrape = SSLScrape.new(scanner, buildchecks)
sslscrape.get_sslscan_results
sslscrape.output
filecreate = FileWriter.new(scanner, buildchecks)
filecreate.iterate_data
