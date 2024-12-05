# Name: Helen Truong
# Date: 12/4/24
# CPE400: Final Project

import pyshark # https://github.com/KimiNewt/pyshark
import asyncio
import argparse

# notes
# - does NOT account for Sheriff role or any other roles that allow crewmates to kill
# - DOES account for Engineer or other roles that allow crewmates to vent

# example terminal inputs
# file capture: python cpefinal.py --method "file" --input "amongus244.pcapng"
# live capture: python cpefinal.py --method "live" --input "Wi-Fi"
# default: python cpefinal.py
# - default is the same as live capture

# referenced https://youtu.be/3A2kMwnBlEU?si=Lq7jmfP6vOHE3ns3 
# referenced https://github.com/lesander/amongus-impostor-detector/blob/main/detector.py

# amongus filter: https://github.com/cybershard/wireshark-amongus
    # modifications to lua file:
    # - changed bit32 to bit to resolve error
    # - had to make sure 2nd and 3rd parameters in string.sub on line 251 were int
# get only reliable packets from Among Us
stream_filter = "amongus and amongus.packet_format eq Reliable"

# ayncio fix for RunTimeError: https://github.com/KimiNewt/pyshark/issues/674
loop = asyncio.ProactorEventLoop()
asyncio.set_event_loop(loop)

# get command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--method", default="live", help="Analyze a file.", type=str)
parser.add_argument("--input", default="Wi-Fi", help="File name or interface for live capture.", type=str)
args = parser.parse_args()

# check command line arguments for live or file capture
if args.method == "live":
    cap = pyshark.LiveCapture(args.input, eventloop=loop, display_filter=stream_filter)
elif args.method == "file":
    cap = pyshark.FileCapture(args.input, eventloop=loop, display_filter=stream_filter)

players = []
imposters = []
suspects = []
crewmates = []
dead = []

def print_notes():
    print("Confirmed Identities:")
    print(f"Crewmates: {crewmates}")
    print(f"Imposters: {imposters}")
    print(f"Dead: {dead}\n")

    print(f"Suspects: {suspects}\n")
    

# reset notes when a new game starts
def new_game():
    players.clear()
    imposters.clear()
    crewmates.clear()
    suspects.clear()
    dead.clear()

# analyze packets
for packet in cap:
    data = packet.amongus._get_all_fields_with_alternates()
    field_count = 0

    if packet.amongus.payload_type == "2": # StartGame
        new_game()
        print("\n------------------------------------------")
        print("New game started.")
        print("------------------------------------------\n")
    elif packet.amongus.payload_type == "5": # GameData
        for field in data:

            # get chat log
            if "SendChat" in str(field) and data[field_count+2].showname_value != "0":
                player = data[field_count-1].showname_value
                chat = data[field_count+2].showname_value
                print(f"{player}: {chat}")

            # get players who enter vents
                # gives hint to who the imposter is
                # not a perfect method because there is the Engineer role in the game where a crewmate player can use vents
            if "EnterVent" in str(field):
                player = data[field_count-1].showname_value
                player_id = int(player) - 1
                player = str(player_id)
                print(f"Player {player} entered a vent.")
                if player not in suspects and player not in imposters:
                    suspects.append(player)
            
            # get players who exit vents
                # gives hint to who the imposter is
                # not a perfect method because there is the Engineer role in the game where a crewmate player can use vents
            if "ExitVent" in str(field):
                player = data[field_count-1].showname_value
                player_id = int(player) - 1
                player = str(player_id)
                print(f"Player {player} exited a vent.")
                if player not in suspects and player not in imposters:
                    suspects.append(player)
            
            if "StartMeeting" in str(field):
                print("\nMeeting starts.\n")

                # get confirmed crewmates and imposters and suspects to be ready for the meeting
                print_notes()

            if "VotingComplete" in str(field):
                print("\nVoting ends.\n")

            # determine who the crewmates are
                # may not get all the crewmates if the player doesn't do any tasks at all
            if "CompleteTask" in str(field):
                player = data[field_count-1].showname_value
                print(f"Player {player} completed a task.")
                if player not in crewmates:
                    crewmates.append(player)
            
            # determine who the imposters are
                # may not get all the imposters if the player doesn't do any murders
                # removes imposters from suspects list bc they're confirmed imposters
            if "MurderPlayer" in str(field):
                imposter = data[field_count-1].showname_value
                player = data[field_count+1].showname_value
                print(f"Player {imposter} murdered Player {player}.")
                
                # note confirmed imposter
                if imposter not in imposters:
                    imposters.append(imposter)
                if imposter in suspects:
                    suspects.remove(imposter)

                # move crewmate id to dead list
                if player in players:
                    players.remove(player)
                if player in crewmates: 
                    crewmates.remove(player)
                if player in suspects: # if crewmate was engineer
                    suspects.remove(player)
                if player not in dead:
                    dead.append(player)

            if "ReportDeadBody" in str(field):
                player = data[field_count-1].showname_value
                print(f"Player {player} reported a dead body.")
                
            field_count += 1




