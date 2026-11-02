package agents

import "testing"

func TestAConversationRoomBelongsToOnePerson(t *testing.T) {
	mine := roomNameFor("ten_acme", "usr_a", "conv-assistant.1.3")
	theirs := roomNameFor("ten_acme", "usr_b", "conv-assistant.1.3")
	if mine == theirs {
		t.Fatalf("two people share %s", mine)
	}
	if mine != "ten_acme__usr_a__conv-assistant.1.3" {
		t.Fatalf("room = %s", mine)
	}
}

func TestOtherRoomsStayShared(t *testing.T) {
	if a, b := roomNameFor("ten_acme", "usr_a", "standup"), roomNameFor("ten_acme", "usr_b", "standup"); a != b || a != "ten_acme__standup" {
		t.Fatalf("rooms = %s, %s", a, b)
	}
	if room := roomNameFor("ten_acme", "usr_a", "my-conv-1"); room != "ten_acme__my-conv-1" {
		t.Fatalf("room = %s", room)
	}
}

func TestNoRoomNameReachesIntoSomeoneElsesConversation(t *testing.T) {
	for _, room := range []string{"usr_b__conv-assistant.1.3", "a__b"} {
		if validRoom(room) {
			t.Fatalf("%s was accepted", room)
		}
	}
	for _, room := range []string{"standup", "my_room", "conv-assistant.1.3"} {
		if !validRoom(room) {
			t.Fatalf("%s was refused", room)
		}
	}
}
