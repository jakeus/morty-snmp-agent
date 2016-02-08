package com.jakeus.morty;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream.GetField;

import org.snmp4j.TransportMapping;
import org.snmp4j.agent.BaseAgent;
import org.snmp4j.agent.CommandProcessor;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOGroup;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.MOTableRow;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB.SnmpCommunityEntryRow;
import org.snmp4j.agent.mo.snmp.SnmpNotificationMIB;
import org.snmp4j.agent.mo.snmp.SnmpTargetMIB;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.transport.TransportMappings;

public class Morty extends BaseAgent 
{
	public static void main(String args[])
	{
		byte[] localEngineID = MPv3.createLocalEngineID();
		OctetString octetString = new OctetString(localEngineID);		
		CommandProcessor cp = new CommandProcessor(octetString);
		
		File bootCounterFile = new File("/home/comet5jp/test.txt");
		File configFile = new File("/home/comet5jp/configFile.txt");
		Morty agent = new Morty(bootCounterFile, configFile, cp);

		try 
		{
			agent.init();
			agent.setSysDescr(new OctetString("hello world"));
			agent.addShutdownHook();
			agent.getServer().addContext(new OctetString("public"));
			agent.finishInit();
			agent.run();
			agent.sendColdStartNotification();
			while(true) {
				Thread.sleep(1000);
			}
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		} 
		catch (InterruptedException e) 
		{
			e.printStackTrace();
		}
		System.out.println("DONE!");
	}
	protected Morty(File bootCounterFile, File configFile, CommandProcessor commandProcessor) 
	{
		super(bootCounterFile, configFile, commandProcessor);
	}

	@Override
	protected void addCommunities(SnmpCommunityMIB communityMIB) 
	{
		Variable[] com2sec = new Variable[] {
				new OctetString("public"), // community name
				new OctetString("cpublic"), // security name
				getAgent().getContextEngineID(), // local engine ID
				new OctetString("public"), // default context name
				new OctetString(), // transport tag
				new Integer32(StorageType.nonVolatile), // storage type
				new Integer32(RowStatus.active) // row status
		};
		
		MOTableRow row = communityMIB.getSnmpCommunityEntry().createRow(
				new OctetString("public2public").toSubIndex(true), com2sec);
		
		communityMIB.getSnmpCommunityEntry().addRow((SnmpCommunityEntryRow) row);
		
		final OID interfacesTable = new OID(".1.3.6.1.4.1.44.1");
		
		
	}

	@Override
	protected void addNotificationTargets(SnmpTargetMIB arg0, SnmpNotificationMIB arg1) 
	{
		System.out.println("HERE");
	}

	@Override
	protected void addUsmUser(USM arg0) 
	{
		System.out.println("HERE");
	}

	@Override
	protected void addViews(VacmMIB vacm) 
	{
		vacm.addGroup(SecurityModel.SECURITY_MODEL_SNMPv2c, new OctetString(
				"cpublic"), new OctetString("v1v2group"),
				StorageType.nonVolatile);
 
		vacm.addAccess(new OctetString("v1v2group"), new OctetString("public"),
				SecurityModel.SECURITY_MODEL_ANY, SecurityLevel.NOAUTH_NOPRIV,
				MutableVACM.VACM_MATCH_EXACT, new OctetString("fullReadView"),
				new OctetString("fullWriteView"), new OctetString(
						"fullNotifyView"), StorageType.nonVolatile);
 
		vacm.addViewTreeFamily(new OctetString("fullReadView"), new OID("1.3"),
				new OctetString(), VacmMIB.vacmViewIncluded,
				StorageType.nonVolatile);
	}

	protected void registerManagedObjects(ManagedObject mo) 
	{
		try {
			server.register(mo, null);
		} catch (DuplicateRegistrationException ex) {
			throw new RuntimeException(ex);
		}
	}

	protected void unregisterManagedObjects(MOGroup moGroup) 
	{
		moGroup.unregisterMOs(server, getContext(moGroup));
	}
	
	@Override
	protected void initTransportMappings() throws IOException {
		transportMappings = new TransportMapping[1];
		Address addr = GenericAddress.parse("0.0.0.0/16100");
		TransportMapping tm = TransportMappings.getInstance().createTransportMapping(addr);
		transportMappings[0] = tm;
	}
	@Override
	protected void registerManagedObjects() {
		// TODO Auto-generated method stub
		
	}
	@Override
	protected void unregisterManagedObjects() {
		// TODO Auto-generated method stub
		
	}
}
