##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'SMB Session Pipe Auditor',
      'Description' => 'Determine what named pipes are accessible over SMB',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    deregister_options('RPORT')
  end

  @@target_pipes = [
    'netlogon',
    'lsarpc',
    'samr',
    'browser',
    'atsvc',
    'DAV RPC SERVICE',
    'epmapper',
    'eventlog',
    'InitShutdown',
    'keysvc',
    'lsass',
    'spoolss',
    'net\NtControlPipe0',
    'net\NtControlPipe1',
    'net\NtControlPipe2',
    'net\NtControlPipe3',
    'net\NtControlPipe4',
    'net\NtControlPipe5',
    'net\NtControlPipe6',
    'net\NtControlPipe7',
    'net\NtControlPipe8',
    'net\NtControlPipe9',
    'PCHHangRepExecPipe',
    'PCHFaultRepExecPipe',
    'TerminalServer\AutoReconnect',
    '360OnAccessSet',
    '360OnAccessGet',
    'winlogonrpc',
    'SfcApi',
    'dmserver.pnp.dadmin',
    'gecko-crash-server-pipe.196',
    'aswUpdSv',
    'afwCallbackPipe2',
    'aswUpdSv',
    'AVG7B14C58C-E30D-11DB-B553-F88A56D89593',
    'AvgFwS8.WDCommunicationPipe1',
    'AvgFwS8.WDCommunicationPipe2',
    'AvgTrayPipeName000176',
    'AvgTrayPipeName0001761',
    'AvgTrayPipeName0001762',
    'AvgFwS8.WDCommunicationPipe',
    '_pspuser_3620_AVGIDSMONITOR.EXE_9fde9445-f261-4985-a056-fb033d1a64cd',
    'AVG-CHJW-0B47172B-B945-42f8-AA88-8D4F98F660DB',
    'AVG-CHJW-C81C2B71-E0F0-44cb-B6A7-15999D0F539A',
    'AvgFw.WDCommunicationPipe',
    'AvgFw.WDCommunicationPipe1',
    'AvgFw.WDCommunicationPipe2',
    'AvgTrayPipeName000840',
    'AvgTrayPipeName0008401',
    'AvgTrayPipeName0008402',
    'AvgUIPipeName002788',
    'AvgUIPipeName0027881',
    'AvgUIPipeName0027882',
    'AveSvc_EngineDienst200705311802',
    'AveSvc_EngineService2008',
    'avguard01',
    'AVSCAN_REP_000000000000c883',
    'AVWebCatServer0',
    'AVWebGuardServer',
    'AVWebProtServer0',
    'SERVERPIPENAME',
    'AveSvc_EngineService2008',
    'bdantiphishing',
    'bdantispam',
    'EXTREG',
    'LIVESRV',
    'MIDASCOMM_SERVER',
    'VSSERV',
    '__fships_hook_server__',
    '__fships_injector__',
    'rcn_18871562230061',
    'rcn_49140823412',
    'rcn_491711751329',
    'rcn_50406860721',
    'rcn_507341306237',
    'rcn_51109653602',
    'rcn_520781201855',
    'rcn_520932065562',
    'rcn_520932267096',
    'rcn_522811486723',
    'rcn_530461792332',
    'rcn_53156781683',
    'rcn_564531165073',
    'rcn_580461750377',
    'rcn_621562061643',
    'rcn_637501693024',
    'rcn_63750782962',
    'rcn_647032361703',
    'rcn_655781047893',
    'rcn_655931694327',
    'rcn_662811357824',
    'rcn_67953938451',
    'rcn_682651449794',
    'rcn_685151921711',
    'nai_vseconsole01',
    'Symantec_{F9698F61-2E57-469B-B29B-1EFB17827356}_{0C55C096-0F1D-4F28-AAA2-85EF591126E7}',
    'Symantec Core LC',
    'Symantec_{586D4B8E-3DBB-4E4O-9A7E-4670F760FAC4}_{0C55C096-0F1D-4F28-AAA2-85EF591126E7}',
    'Symantec_{EF903280-DA47-4C1B-99F8-EC15E7900956}_{0C55C096-0F1D-4F28-AAA2-85EF591126E7}',
    'acsipc_server',
    'pavfnlpc',
    'Global\PNMIPC_SH_IPT-WebProxy',
    'PavTPU\TPK_Event_1504',
    'Sophos@BOPSv3',
    'NP2970625197SRV',
    'vmware-usbarbpipe',
    'LSM_API_service',
    'ntsvcs',
    'plugplay',
    'protected_storage',
    'router',
    'SapiServerPipeS-1-5-5-0-70123',
    'scerpc',
    'srvsvc',
    'tapsrv',
    'trkwks',
    'W32TIME_ALT',
    'wkssvc',
    'PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER',
    'db2remotecmd'
  ]

  # Fingerprint a single host
  def run_host(ip)

    pass = []

    [[139, false], [445, true]].each do |info|

    datastore['RPORT'] = info[0]
    datastore['SMBDirect'] = info[1]

    begin
      connect()
      smb_login()
      @@target_pipes.each do |pipe|
        begin
          fid = smb_create("\\#{pipe}")
          #print_status("Opened pipe \\#{pipe}")
          pass.push(pipe)
        rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
          #print_error("Could not open \\#{pipe}: Error 0x%.8x" % e.error_code)
        end
      end

      disconnect()

      break
    rescue ::Exception => e
      #print_line($!.to_s)
      #print_line($!.backtrace.join("\n"))
    end
    end

    if(pass.length > 0)
      print_status("Pipes: #{pass.map{|c| "\\#{c}"}.join(", ")}")
      # Add Report
      report_note(
        :host	=> ip,
        :proto => 'tcp',
        :sname	=> 'smb',
        :port	=> rport,
        :type	=> 'Pipes Founded',
        :data	=> "Pipes: #{pass.map{|c| "\\#{c}"}.join(", ")}"
      )
    end
  end


end
